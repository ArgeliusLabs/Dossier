"""Static code analysis of the extension's JS/HTML/JSON with aggressive noise suppression.

Design principles (the whole point of this tool):
  * Comments are stripped before anything is matched, so licence headers and doc links vanish.
  * Recognised third-party libraries are identified and their matches are *counted, not reported*.
  * Well-known benign idioms (e.g. ``Function("return this")``) are whitelisted.
  * One finding per behaviour, with a handful of evidence locations, never one per match.
  * No IP-address, crypto-address, or e-mail scraping: those generate noise, not signal.
  * Minified code is normal and is never reported as obfuscation; only real obfuscator markers are.
"""
from __future__ import annotations

import bisect
import ipaddress
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .knowledge import (
    BENIGN_DYNAMIC_CODE, CDN_DOMAINS, CODE_HOSTING, LIBRARY_FILENAME, LIBRARY_SIGNATURES,
    NOISE_URL_PATTERNS, PLACEHOLDER_HOST, STORE_DOMAINS, TRACKERS, registrable_domain,
)
from .models import Endpoint, Evidence, Finding, Library

MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_EVIDENCE = 5

# ------------------------------------------------------------------ lexing -------------

_TOKEN = re.compile(
    r"""(?P<lc>//[^\n]*)"""
    r"""|(?P<bc>/\*.*?\*/)"""
    r"""|(?P<s>"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)""",
    re.S,
)


@dataclass
class JsFile:
    rel: str
    text: str           # original text
    code: str           # comments blanked out (same length/offsets as text)
    strings: list[tuple[int, str]]  # (offset, inner string value)
    lines: list[int]    # offsets of newline chars, for line lookup
    library: str = ""   # library name if the whole file is a known library
    is_bundle: bool = False
    is_data: bool = False   # mostly string data (filter lists, rule sets, dictionaries)
    role: set[str] = field(default_factory=set)   # content_script, background, page

    def in_string(self, pos: int) -> bool:
        """True if ``pos`` falls inside a string literal (so a match there is data, not a call)."""
        if not hasattr(self, "_starts"):
            self._starts = [o for o, _ in self.strings]
        i = bisect.bisect_right(self._starts, pos) - 1
        if i < 0:
            return False
        o, inner = self.strings[i]
        return o < pos < o + len(inner) + 1

    def line_of(self, pos: int) -> int:
        return bisect.bisect_right(self.lines, pos) + 1

    def snippet(self, pos: int, end: int | None = None, before: int = 70, after: int = 130) -> str:
        ls = self.text.rfind("\n", 0, pos) + 1
        le = self.text.find("\n", pos)
        le = len(self.text) if le < 0 else le
        a = max(ls, pos - before)
        b = min(le, (end or pos) + after)
        s = self.text[a:b].strip()
        return ("…" if a > ls else "") + s + ("…" if b < le else "")


def lex(rel: str, text: str) -> JsFile:
    code = list(text)
    strings: list[tuple[int, str]] = []
    for m in _TOKEN.finditer(text):
        kind = m.lastgroup
        if kind in ("lc", "bc"):
            # Guard: '//' inside a regex literal such as /https?:\/\// is escaped, so we are
            # fairly safe; blank out the comment keeping newlines for line numbering.
            for i in range(m.start(), m.end()):
                if code[i] != "\n":
                    code[i] = " "
        else:
            strings.append((m.start(), m.group()[1:-1]))
    lines = [m.start() for m in re.finditer("\n", text)]
    return JsFile(rel, text, "".join(code), strings, lines)


# ------------------------------------------------------------------ rules --------------

@dataclass
class Rule:
    id: str
    category: str
    severity: str
    title: str
    detail: str
    pattern: re.Pattern
    opsec: str = ""
    content_script_only: bool = False
    check: callable = None   # optional (file, match) -> bool to accept a hit


def _arg_is_literal(js: JsFile, m: re.Match) -> bool:
    rest = js.code[m.end():m.end() + 3].lstrip()
    return rest[:1] in ("'", '"', "`") and not rest.startswith("`${")


def _dynamic_code_ok(js: JsFile, m: re.Match) -> bool:
    window = js.code[m.start():m.start() + 120]
    if any(p.search(window) for p in BENIGN_DYNAMIC_CODE):
        return False
    # Ignore property names like obj.eval( or "evaluate("
    before = js.code[max(0, m.start() - 1):m.start()]
    if before in (".", "$", "_", "/", "|") or before.isalnum():
        return False   # property access, identifier suffix, or inside a regex literal like /Function(?:...)/
    if js.code[m.end():m.end() + 1] == "?":
        return False   # regex group "(?:" - this is a regex literal, not a call
    return not _arg_is_literal(js, m)


def _remote_script_inject(js: JsFile, m: re.Match) -> bool:
    window = js.code[m.start():m.start() + 500]
    if re.search(r"getURL\s*\(|runtime\.getURL|extension\.getURL|chrome-extension://|moz-extension://", window):
        return False
    return bool(re.search(r"\.src\s*=\s*(?!['\"`](?:data:|blob:|chrome|moz))|setAttribute\(\s*['\"]src['\"]", window))


RULES: list[Rule] = [
    # ---------------- remote / dynamic code -------------------------------------------
    Rule("code.eval", "remote_code", "medium", "Executes dynamically built code (eval)",
         "eval() runs a string as code. When that string comes from a server, the extension can run code that "
         "was never in the reviewed package.",
         re.compile(r"(?<![\w$.])eval\s*\("), check=_dynamic_code_ok),
    Rule("code.new_function", "remote_code", "medium", "Builds functions from strings (new Function)",
         "new Function(...) compiles a string into code at runtime, the same risk as eval().",
         re.compile(r"(?<![\w$.])(?:new\s+)?Function\s*\(\s*(?!\))"), check=_dynamic_code_ok),
    Rule("code.exec_code_string", "remote_code", "high", "Injects code strings into web pages",
         "tabs.executeScript/scripting with a 'code' string injects arbitrary text as code into a page, a classic "
         "way to run server-supplied JavaScript in the sites you visit.",
         re.compile(r"executeScript\s*\([^;]{0,300}?\bcode\s*:")),
    Rule("code.user_scripts", "remote_code", "medium", "Registers user scripts at runtime",
         "The userScripts API runs scripts supplied at runtime, i.e. code that need not exist in the package.",
         re.compile(r"userScripts\s*\.\s*(?:register|execute|configureWorld|update)\s*\(")),
    Rule("code.remote_import", "remote_code", "high", "Loads JavaScript from a remote server",
         "Code is imported from an http(s) URL at runtime. The server owner can change what runs at any time.",
         re.compile(r"""(?:importScripts|import)\s*\(\s*['"`]https?://""")),
    Rule("code.script_inject", "remote_code", "medium", "Adds external <script> tags to pages",
         "Creates a script element whose source is not one of the extension's own files. If that source is remote, "
         "the server controls code running in the page.",
         re.compile(r"""createElement\s*\(\s*['"]script['"]\s*\)"""), check=_remote_script_inject),

    # ---------------- data access ------------------------------------------------------
    Rule("data.cookies_api", "data_access", "medium", "Reads browser cookies through the extension API",
         "Calls the cookies API to read cookies, which include login session tokens.",
         re.compile(r"\bcookies\s*\.\s*(?:getAll|get|getAllCookieStores)\s*\("),
         opsec="Check where cookie values are sent. Cookie values leaving the browser equals session hijack."),
    Rule("data.document_cookie", "data_access", "low", "Reads website cookies from inside pages",
         "Content script reads document.cookie on the pages you visit.",
         re.compile(r"document\s*\.\s*cookie\b(?!\s*=[^=])"), content_script_only=True),
    Rule("data.history_api", "data_access", "high", "Queries your browsing history",
         "Calls the history API to search or enumerate the sites you have visited.",
         re.compile(r"\bhistory\s*\.\s*(?:search|getVisits)\s*\(")),
    Rule("data.request_body", "data_access", "high", "Reads form/POST data you submit",
         "Listens to web requests and asks for request bodies, which contain whatever you submit in forms "
         "(search terms, messages, sometimes credentials).",
         re.compile(r"onBeforeRequest[\s\S]{0,400}?['\"]requestBody['\"]")),
    Rule("data.keystrokes", "data_access", "low", "Listens to your keystrokes in web pages",
         "A content script listens for key/input events on pages. Often used for shortcuts, but this is also how "
         "keyloggers work; check whether typed data is sent anywhere.",
         re.compile(r"""addEventListener\s*\(\s*['"](?:keydown|keyup|keypress|input|beforeinput)['"]"""),
         content_script_only=True),
    Rule("data.password_fields", "data_access", "medium", "Interacts with password fields",
         "Content script targets password inputs on pages. Expected for password managers; unexpected anywhere else.",
         re.compile(r"""type\s*=\s*\\?['"]?password|input\[type=\\?['"]?password|\.type\s*===?\s*['"]password['"]"""),
         content_script_only=True),
    Rule("data.clipboard_read", "data_access", "medium", "Reads the clipboard",
         "Reads clipboard contents, which often hold passwords, 2FA codes or case notes.",
         re.compile(r"clipboard\s*\.\s*read(?:Text)?\s*\(|execCommand\s*\(\s*['\"]paste['\"]")),
    Rule("data.screenshot", "data_access", "medium", "Takes screenshots of your tabs",
         "captureVisibleTab / tab capture grabs an image of what you are viewing.",
         re.compile(r"captureVisibleTab\s*\(|tabCapture\s*\.\s*capture\s*\(|getDisplayMedia\s*\(")),
    Rule("data.media", "data_access", "medium", "Requests camera or microphone",
         "Calls getUserMedia to access camera/microphone.",
         re.compile(r"getUserMedia\s*\(")),
    Rule("data.geolocation", "data_access", "medium", "Requests your physical location",
         "Uses the Geolocation API.",
         re.compile(r"geolocation\s*\.\s*(?:getCurrentPosition|watchPosition)\s*\(")),
    Rule("data.profile_email", "data_access", "high", "Reads the email of your browser profile",
         "identity.getProfileUserInfo returns the signed-in Google account email, directly identifying you.",
         re.compile(r"getProfileUserInfo\s*\(")),
    Rule("data.hook_network", "data_access", "high", "Hooks the website's own network functions",
         "Overrides fetch/XMLHttpRequest inside pages, letting it read every API response the site receives "
         "(e.g. messages, AI chat transcripts, account data) before you see it.",
         re.compile(r"(?:window|globalThis|self)\s*\.\s*fetch\s*=(?!=)|XMLHttpRequest\s*\.\s*prototype\s*\.\s*(?:open|send|setRequestHeader)\s*=(?!=)"),
         opsec="This is the technique used by extensions caught harvesting AI-chat conversations."),

    # ---------------- control over the browser -----------------------------------------
    Rule("ctl.debugger", "control", "critical", "Attaches the debugger to tabs",
         "chrome.debugger.attach gives full DevTools control of a tab: all network traffic, cookies and page contents.",
         re.compile(r"debugger\s*\.\s*attach\s*\(")),
    Rule("ctl.native", "control", "high", "Talks to a native program on your computer",
         "Native messaging hands data to a program outside the browser sandbox.",
         re.compile(r"connectNative\s*\(|sendNativeMessage\s*\(")),
    Rule("ctl.manage_ext", "control", "high", "Disables or removes other extensions",
         "Can switch off or uninstall your other extensions, e.g. security tools or competitors.",
         re.compile(r"management\s*\.\s*(?:setEnabled|uninstall)\s*\(")),
    Rule("ctl.list_ext", "fingerprinting", "medium", "Enumerates your installed extensions",
         "Lists every extension you have installed, a strong fingerprint that also reveals your toolset.",
         re.compile(r"management\s*\.\s*getAll\s*\(")),
    Rule("ctl.privacy", "control", "medium", "Changes browser privacy settings",
         "Writes to chrome.privacy settings (WebRTC, prediction, referrers, etc.).",
         re.compile(r"privacy\s*\.\s*(?:network|services|websites)\s*\.\s*\w+\s*\.\s*set\s*\(")),
    Rule("ctl.proxy", "control", "high", "Routes your traffic through a proxy",
         "Configures the browser proxy, sending traffic through servers chosen by the extension.",
         re.compile(r"proxy\s*\.\s*settings\s*\.\s*set\s*\(|proxy\s*\.\s*onRequest\s*\.\s*addListener|proxy\s*\.\s*register\s*\(")),
    Rule("ctl.dynamic_rules", "control", "low", "Changes its request rules at runtime",
         "Updates declarativeNetRequest rules dynamically. If the rules come from a server, the vendor can "
         "redirect or rewrite your traffic remotely.",
         re.compile(r"update(?:Dynamic|Session)Rules\s*\(")),

    # ---------------- tracking / fingerprinting ---------------------------------------------
    Rule("fp.canvas", "fingerprinting", "low", "Uses canvas/WebGL/audio fingerprinting techniques",
         "Reads back rendered canvas/WebGL/audio data, a standard way to build a unique device fingerprint.",
         re.compile(r"UNMASKED_(?:RENDERER|VENDOR)_WEBGL|createOscillator\s*\([\s\S]{0,400}?getChannelData|"
                    r"getContext\(\s*['\"]2d['\"]\s*\)[\s\S]{0,300}?fillText[\s\S]{0,300}?toDataURL")),
    Rule("net.uninstall_url", "network", "low", "Reports your uninstall to a server",
         "setUninstallURL opens a vendor page when you remove the extension, usually with tracking parameters that "
         "tie the uninstall back to your install ID.",
         re.compile(r"setUninstallURL\s*\(")),
    Rule("net.beacon", "network", "low", "Sends background beacons",
         "navigator.sendBeacon fires data to a server even as pages close; typical of analytics/telemetry.",
         re.compile(r"sendBeacon\s*\(")),
]

OBFUSCATION_MARKERS = [
    ("javascript-obfuscator (_0x names)", re.compile(r"\b_0x[0-9a-f]{4,6}\b"), 25),
    ("Dean Edwards packer", re.compile(r"eval\(function\(p,a,c,k,e,[dr]\)"), 1),
    ("JSFuck", re.compile(r"\[\]\[\(!\[\]\+\[\]\)"), 1),
    ("hex-escaped strings", re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}"), 40),
]

SECURITY_HEADERS = re.compile(
    r"""['"](?:content-security-policy(?:-report-only)?|x-frame-options|strict-transport-security|"""
    r"""cross-origin-opener-policy|cross-origin-embedder-policy|x-content-type-options)['"]""", re.I)

REQUEST_CONTEXT = re.compile(
    r"fetch\s*\(|XMLHttpRequest|\.open\s*\(\s*['\"](?:GET|POST|PUT)|axios|\$\.(?:ajax|get|post|getJSON)|"
    r"sendBeacon|WebSocket\s*\(|EventSource\s*\(|importScripts|\.src\s*=|\bsrc\s*:|"
    r"\w*(?:endpoint|baseurl|api|host|server|collect|track|telemetry|report|url)\w*['\"]?\s*[:=]\s*['\"`]?$|"
    r"setUninstallURL",
    re.I,
)

URL_IN_STRING = re.compile(r"""(?:https?|wss?)://[^\s'"`<>\\)]+""", re.I)


@dataclass
class CodeScanResult:
    findings: list[Finding]
    endpoints: list[Endpoint]
    libraries: list[Library]
    noise: Counter
    stats: dict
    snippets_for_llm: list[dict]


def _detect_library(rel: str, text: str) -> tuple[str, str]:
    head = text[:4000]
    for name, pat in LIBRARY_SIGNATURES:
        m = pat.search(head)
        if m:
            ver = next((g for g in m.groups() if g), "") if m.groups() else ""
            return name, ver
    if LIBRARY_FILENAME.search(rel):
        if re.search(r"vendors?", Path(rel).name, re.I):
            return "Third-party vendor bundle", ""
        return Path(rel).name.split(".")[0], ""
    return "", ""


def _content_script_files(manifest: dict) -> set[str]:
    out = set()
    for cs in manifest.get("content_scripts", []) or []:
        if isinstance(cs, dict):
            out.update(str(j).lstrip("/").replace("\\", "/") for j in cs.get("js", []) or [])
    return out


def _background_files(manifest: dict) -> set[str]:
    bg = manifest.get("background") or {}
    out = set()
    if isinstance(bg, dict):
        if bg.get("service_worker"):
            out.add(str(bg["service_worker"]).lstrip("/"))
        out.update(str(s).lstrip("/") for s in bg.get("scripts", []) or [])
    return out


def _is_valid_host(host: str) -> bool:
    if not host or PLACEHOLDER_HOST.search(host):
        return False
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_reserved)
    except ValueError:
        pass
    return bool(re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}", host))


def classify_host(host: str, url: str, first_party: set[str]) -> tuple[str, str]:
    h = host.lower()
    hp = (h + urllib_path(url)).lower()
    for key, (cat, label) in TRACKERS.items():
        if "/" in key:
            if hp.startswith(key) or ("." + key) in hp:
                return cat, label
        elif h == key or h.endswith("." + key):
            return cat, label
    for key, label in CODE_HOSTING.items():
        if "/" in key:
            if hp.startswith(key):
                return "code_hosting", label
        elif h == key or h.endswith("." + key):
            return "code_hosting", label
    if h in CDN_DOMAINS:
        return "cdn", CDN_DOMAINS[h]
    if h in STORE_DOMAINS or h.endswith(".mozilla.org") or h.endswith(".mozilla.net"):
        return "store", "Browser vendor / store"
    own = registrable_domain(h) in first_party
    if _ANALYTICS_HOSTNAME.match(h):
        return "analytics", "Publisher's own analytics" if own else "Analytics (by hostname)"
    if own:
        return "first_party", "Publisher domain"
    return "unknown", ""


_ANALYTICS_HOSTNAME = re.compile(
    r"^(?:[\w-]+[.-])?(?:analytics|stats|statistics|telemetry|tracking|tracker|track|collect|collector|metrics|"
    r"events?|beacon|pixel|logs?|logging|clickstream|insights)(?:[-\d][\w-]*)?\.", re.I)


def urllib_path(url: str) -> str:
    m = re.match(r"^[a-z]+://[^/]+(/[^?#]*)?", url, re.I)
    return (m.group(1) or "") if m else ""


def scan(root: Path, manifest: dict, first_party_domains: set[str]) -> CodeScanResult:
    noise: Counter = Counter()
    findings_hits: dict[str, list[tuple[JsFile, int, int]]] = defaultdict(list)
    libraries: dict[tuple[str, str], Library] = {}
    endpoints: dict[str, Endpoint] = {}
    stats = Counter()
    cs_files = _content_script_files(manifest)
    bg_files = _background_files(manifest)
    extra_findings: list[Finding] = []
    first_party_js: list[JsFile] = []

    files = sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink())
    for p in files:
        rel = p.relative_to(root).as_posix()
        ext = p.suffix.lower()
        stats["files"] += 1
        try:
            size = p.stat().st_size
        except OSError:
            continue
        stats["bytes"] += size
        if ext == ".wasm":
            stats["wasm"] += 1
            extra_findings.append(Finding("code.wasm", "remote_code", "low", "Contains compiled WebAssembly",
                                          "WebAssembly is compiled binary code that cannot be read like JavaScript. Usually "
                                          "legitimate (codecs, crypto, parsers), but it hides logic from review.",
                                          [Evidence(rel, None, f"{size:,} bytes")]))
            continue
        if ext not in (".js", ".mjs", ".cjs", ".html", ".htm", ".json"):
            continue
        if size > MAX_FILE_BYTES:
            noise["files too large to scan"] += 1
            continue
        text = p.read_bytes().decode("utf-8", "replace")

        if ext in (".html", ".htm"):
            _scan_html(rel, text, endpoints, extra_findings, first_party_domains, noise)
            continue
        if ext == ".json":
            if rel.startswith("_locales/") or rel in ("manifest.json",):
                continue
            _scan_json(rel, text, extra_findings)
            continue

        stats["js_files"] += 1
        stats["js_bytes"] += size
        js = lex(rel, text)
        if rel in cs_files:
            js.role.add("content_script")
        if rel in bg_files:
            js.role.add("background")
        lib, ver = _detect_library(rel, text)
        js.library = lib
        str_bytes = sum(len(x) for _, x in js.strings)
        js.is_data = size > 4_000 and str_bytes > 0.6 * len(text)
        js.is_bundle = "__webpack_require__" in text or "webpackChunk" in text or "parcelRequire" in text
        if lib:
            key = (lib, ver)
            libraries.setdefault(key, Library(lib, ver)).files.append(rel)
            stats["library_js_bytes"] += size
        else:
            first_party_js.append(js)
            stats["first_party_js_bytes"] += size

        # ---- behaviour rules ----
        for rule in RULES:
            if rule.content_script_only and "content_script" not in js.role and not js.is_bundle:
                continue
            for m in rule.pattern.finditer(js.code):
                if js.in_string(m.start()):
                    noise["code-like text inside string literals (filter lists, messages)"] += 1
                    continue
                if rule.check and not rule.check(js, m):
                    if rule.id in ("code.eval", "code.new_function"):
                        noise["benign eval/Function idioms (polyfills, bundler shims, literal strings)"] += 1
                    continue
                if lib:
                    noise["behaviour matches inside known third-party libraries"] += 1
                    continue
                findings_hits[rule.id].append((js, m.start(), m.end()))

        # ---- obfuscation (first-party only) ----
        if not lib:
            for label, pat, threshold in OBFUSCATION_MARKERS:
                hits = pat.findall(js.code)
                if len(hits) >= threshold:
                    m = pat.search(js.code)
                    extra_findings.append(Finding(
                        "code.obfuscated", "obfuscation", "high", "Code is deliberately obfuscated",
                        f"{rel} contains {len(hits):,} {label} markers. Obfuscation (as opposed to normal minification) "
                        "is prohibited by the Chrome Web Store because its only purpose is to hide what the code does.",
                        [Evidence(rel, js.line_of(m.start()), js.snippet(m.start()))],
                        opsec="Assume the author did not want this reviewed."))
                    break
            _check_blobs(js, extra_findings, noise)
            _check_secrets(js, extra_findings)

        # ---- endpoints from string literals ----
        _collect_endpoints(js, endpoints, first_party_domains, noise)

    findings = _build_rule_findings(findings_hits)
    findings += _merge_extra(extra_findings)
    findings += _fetch_eval_combo(first_party_js)
    llm_snippets = _llm_snippets(findings_hits, endpoints, first_party_js)
    stats["libraries"] = len(libraries)
    return CodeScanResult(findings, sorted(endpoints.values(), key=_endpoint_sort), list(libraries.values()),
                          noise, dict(stats), llm_snippets)


def _endpoint_sort(e: Endpoint):
    order = ["session_recording", "advertising", "code_hosting", "remote_config", "affiliate", "analytics",
             "telemetry", "unknown", "first_party", "cdn", "store"]
    return (e.in_library_only, not e.request_context, order.index(e.category) if e.category in order else 99, e.host)


def _build_rule_findings(hits: dict[str, list[tuple[JsFile, int, int]]]) -> list[Finding]:
    rules = {r.id: r for r in RULES}
    out = []
    for rid, items in hits.items():
        r = rules[rid]
        evidence, seen = [], set()
        for js, s, e in items:
            key = (js.rel, js.line_of(s), js.snippet(s, e)[:80])
            if key in seen:
                continue
            seen.add(key)
            if len(evidence) < MAX_EVIDENCE:
                role = f" [{', '.join(sorted(js.role))}]" if js.role else ""
                evidence.append(Evidence(js.rel + role, js.line_of(s), js.snippet(s, e)))
        bundle_only = all(js.is_bundle and not js.role for js, _, _ in items)
        conf = "medium" if bundle_only else "high"
        if rid == "data.hook_network" and not any("content_script" in js.role for js, _, _ in items):
            conf = "medium"  # injected page scripts (e.g. ad-blocker scriptlets) also do this legitimately
        files = len({js.rel for js, _, _ in items})
        detail = r.detail + (f" Seen {len(items)} time(s) across {files} file(s)." if len(items) > 1 else "")
        if bundle_only:
            detail += " All hits are inside bundled code, which may include third-party library code."
        out.append(Finding(r.id, r.category, r.severity, r.title, detail, evidence,
                           confidence=conf, opsec=r.opsec, total_hits=len(items)))
    return out


def _merge_extra(items: list[Finding]) -> list[Finding]:
    """Merge repeated extra findings (e.g. several obfuscated files) into one each."""
    by: dict[str, Finding] = {}
    for f in items:
        if f.rule in by:
            g = by[f.rule]
            g.total_hits += 1
            if len(g.evidence) < MAX_EVIDENCE:
                g.evidence += f.evidence
            if f.rule == "code.obfuscated":
                g.detail = f"{g.total_hits} first-party files contain obfuscator markers. " + g.detail.split(". ", 1)[-1]
        else:
            f.total_hits = 1
            by[f.rule] = f
    return list(by.values())


def _fetch_eval_combo(first_party: list[JsFile]) -> list[Finding]:
    """Escalate when the same file downloads something and evaluates dynamic code."""
    ev = []
    for js in first_party:
        has_net = re.search(r"fetch\s*\(|XMLHttpRequest|\$\.(?:ajax|get)", js.code)
        if not has_net:
            continue
        for rid, pat in (("eval", RULES[0].pattern), ("Function", RULES[1].pattern)):
            for m in pat.finditer(js.code):
                if not js.in_string(m.start()) and _dynamic_code_ok(js, m):
                    ev.append(Evidence(js.rel, js.line_of(m.start()), js.snippet(m.start())))
                    break
    if not ev:
        return []
    return [Finding("code.fetch_eval", "remote_code", "high",
                    "Downloads data and executes dynamic code in the same file",
                    "These first-party files both make network requests and run strings as code. This is the shape of "
                    "remote code loading. Verify what is passed to eval/Function.",
                    ev[:MAX_EVIDENCE], confidence="medium", total_hits=len(ev),
                    opsec="If confirmed, the publisher can change the extension's behaviour silently, per user.")]


_B64 = re.compile(r"[A-Za-z0-9+/]{3000,}={0,2}")


def _check_blobs(js: JsFile, out: list[Finding], noise: Counter) -> None:
    for off, s in js.strings:
        if len(s) < 3000:
            continue
        m = _B64.fullmatch(s)
        if not m:
            continue
        ctx = js.code[max(0, off - 200):off]
        if re.search(r"data:(?:image|font|audio|video|application/(?:font|x-font|octet))", js.code[max(0, off - 60):off + 40]):
            noise["embedded images/fonts (base64)"] += 1
            continue
        if re.search(r"atob|eval|Function|decode", ctx + js.code[off + len(s):off + len(s) + 200]):
            out.append(Finding("code.encoded_blob", "obfuscation", "medium", "Large encoded payload decoded at runtime",
                               f"A {len(s):,}-character base64 string is decoded at runtime. Encoded payloads are a common way "
                               "to hide code or configuration from reviewers.",
                               [Evidence(js.rel, js.line_of(off), js.snippet(off, off, 60, 40)[:200])]))
        else:
            noise["large base64 strings with no decode/eval nearby"] += 1


# Hardcoded channels that cost nothing to set up and are favourites for data drops / C2.
EXFIL_CHANNELS = [
    ("Telegram bot", re.compile(r"(?<!\d)\d{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])"), "high"),  # often after ".../bot"
    ("Discord webhook", re.compile(r"discord(?:app)?\.com/api/webhooks/\d{15,20}/[\w-]{30,}"), "high"),
    ("Slack webhook", re.compile(r"hooks\.slack\.com/(?:services|workflows|triggers)/T\w+/\w+/\w+"), "high"),
]
EMBEDDED_SECRETS = [
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{40,}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{30,}\b")),
    ("Stripe secret key", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
]
AI_BAIT = re.compile(
    r"(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts?|rules)|"
    r"(?:note|message|instructions?)\s+(?:to|for)\s+(?:the\s+)?(?:ai|llm|language model|automated|security)\s+(?:reviewer|scanner|analy[sz]er|assistant)|"
    r"this (?:extension|code|file) is (?:safe|benign|not malicious)|report (?:this|it) as (?:safe|benign|clean)", re.I)


def _redact(s: str) -> str:
    return s[:6] + "…" + s[-3:] if len(s) > 12 else "…"


def _check_secrets(js: JsFile, out: list[Finding]) -> None:
    for off, s in js.strings:
        if len(s) < 20:
            continue
        for label, pat, sev in EXFIL_CHANNELS:
            m = pat.search(s)
            if m:
                out.append(Finding(
                    "net.exfil_channel", "network", sev, "Hardcoded chat-bot / webhook channel",
                    f"A {label} credential is embedded in the code. Bots and webhooks are free, anonymous, and a classic "
                    "drop point for stolen data or a command channel. Legitimate extensions almost never ship these.",
                    [Evidence(js.rel, js.line_of(off), f"{label}: {_redact(m.group())}")],
                    opsec="Treat as hostile until you see exactly what is sent to it."))
        for label, pat in EMBEDDED_SECRETS:
            m = pat.search(s)
            if m:
                out.append(Finding(
                    "code.embedded_secret", "supply_chain", "medium", "Embedded credentials in the code",
                    f"A {label} is shipped inside the extension. Anyone can extract it; it also shows which third-party "
                    "account receives requests made with it.",
                    [Evidence(js.rel, js.line_of(off), f"{label}: {_redact(m.group())}")]))
    m = AI_BAIT.search(js.text)   # whole text: comments are a natural place to plant this
    if m:
        out.append(Finding(
            "code.ai_bait", "obfuscation", "medium", "Contains text aimed at AI or automated reviewers",
            "The code contains wording that tries to talk to a reviewer or scanner (e.g. 'ignore previous instructions', "
            "'this extension is safe'). Honest code has no reason to address its reviewer.",
            [Evidence(js.rel, js.line_of(m.start()), js.snippet(m.start(), m.end(), 40, 60))]))


BULK_HOSTS = 30


def _collect_endpoints(js: JsFile, endpoints: dict[str, Endpoint], first_party: set[str], noise: Counter) -> None:
    found = []
    for off, s in js.strings:
        if "://" not in s:
            continue
        for m in URL_IN_STRING.finditer(s):
            # A URL embedded inside a larger string (CSS selector, HTML snippet, UI message, filter rule)
            # is a reference, not a request target - unless it's a src= inside markup.
            if m.start() > 0 and not re.search(r"src\s*=\s*['\"]?$", s[max(0, m.start() - 8):m.start()], re.I):
                noise["URLs embedded in text, HTML, selectors or filter rules"] += 1
                continue
            found.append((off, m.group().rstrip(".,;:")))
    if not found:
        return
    # Filter lists / site databases: many distinct hosts in a file that is mostly string data.
    hosts = {re.sub(r"^[a-z]+://([^/:?#]+).*$", r"\1", u, flags=re.I) for _, u in found}
    if len(hosts) > BULK_HOSTS or js.is_data:
        noise["URLs in bulk data files (filter lists, site databases)"] += len(found)
        return
    for off, url in found:
        req = bool(REQUEST_CONTEXT.search(js.code[max(0, off - 160):off + 1]))
        _add_endpoint(url, js.rel, req, bool(js.library), endpoints, first_party, noise)


def _add_endpoint(url: str, rel: str, req: bool, in_lib: bool, endpoints: dict[str, Endpoint],
                  first_party: set[str], noise: Counter) -> None:
    if any(p.search(url) for p in NOISE_URL_PATTERNS):
        noise["documentation / spec / licence / example URLs"] += 1
        return
    hm = re.match(r"^[a-z]+://(?:[^@/]*@)?(\[[^\]]+\]|[^/:?#]+)", url, re.I)
    if not hm:
        return
    host = hm.group(1).lower()
    if not _is_valid_host(host):
        noise["placeholder, template, private-IP or malformed hosts"] += 1
        return
    if in_lib and not req:
        noise["URLs inside third-party libraries (not used for requests)"] += 1
        return
    cat, label = classify_host(host, url, first_party)
    ep = endpoints.get(host)
    if not ep:
        ep = endpoints[host] = Endpoint(host, registrable_domain(host), cat, label)
    ep.count += 1
    ep.request_context = ep.request_context or req
    ep.in_library_only = ep.in_library_only and in_lib
    short = url if len(url) < 160 else url[:157] + "…"
    if short not in ep.urls and len(ep.urls) < 6:
        ep.urls.append(short)
    if rel not in ep.files and len(ep.files) < 6:
        ep.files.append(rel)


_SCRIPT_SRC = re.compile(r"""<script[^>]+src\s*=\s*['"]((?:https?:)?//[^'"]+)['"]""", re.I)
_IFRAME_SRC = re.compile(r"""<iframe[^>]+src\s*=\s*['"](https?://[^'"]+)['"]""", re.I)
_HTML_URL = re.compile(r"""(?:src|href|action)\s*=\s*['"]((?:https?|wss?):[^'"]+)['"]""", re.I)


def _scan_html(rel, text, endpoints, out, first_party, noise):
    for m in _SCRIPT_SRC.finditer(text):
        url = m.group(1)
        out.append(Finding("code.remote_script_tag", "remote_code", "high", "Extension page loads a remote script",
                           f"{rel} includes a <script> from {url}. That script runs with the extension's privileges and "
                           "can be changed by whoever controls the server, without any store review.",
                           [Evidence(rel, text[:m.start()].count("\n") + 1, m.group(0)[:200])],
                           opsec="The code you audit is not the code you run."))
    for m in _IFRAME_SRC.finditer(text):
        out.append(Finding("ui.remote_iframe", "remote_code", "medium", "Extension UI is loaded from a remote website",
                           f"{rel} embeds {m.group(1)} in an iframe, so the UI (and what it asks you for) can change at any time.",
                           [Evidence(rel, text[:m.start()].count("\n") + 1, m.group(0)[:200])]))
    for m in _HTML_URL.finditer(text):
        is_load = m.group(0).lower().lstrip().startswith(("src", "action"))
        _add_endpoint(m.group(1), rel, is_load, False, endpoints, first_party, noise)


_SEC_HEADER_NAMES = {"content-security-policy", "content-security-policy-report-only", "x-frame-options",
                     "strict-transport-security", "cross-origin-opener-policy", "cross-origin-embedder-policy",
                     "x-content-type-options"}


def _scan_json(rel, text, out):
    """Look for declarativeNetRequest rules that *remove* security headers."""
    if not SECURITY_HEADERS.search(text):
        return
    try:
        data = json.loads(text)
    except ValueError:
        return
    rules = data if isinstance(data, list) else []
    hits = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        for h in ((rule.get("action") or {}).get("responseHeaders") or []):
            if isinstance(h, dict) and h.get("operation") == "remove" and str(h.get("header", "")).lower() in _SEC_HEADER_NAMES:
                hits.append(json.dumps(rule)[:240])
    if hits:
        out.append(Finding("net.strip_headers", "control", "high", "Strips website security headers",
                           f"{len(hits)} request-modification rule(s) remove security headers such as Content-Security-Policy "
                           "or X-Frame-Options from websites, weakening their protection against injected code.",
                           [Evidence(rel, None, h) for h in hits[:3]], total_hits=len(hits)))


def _llm_snippets(hits, endpoints, first_party_js: list[JsFile]) -> list[dict]:
    """Pick a compact set of code excerpts that best show what the extension sends where."""
    out: list[dict] = []
    budget = 24_000
    # 1) evidence around network calls in first-party code
    for js in sorted(first_party_js, key=lambda j: (-("background" in j.role), -("content_script" in j.role), j.rel)):
        for m in re.finditer(r"fetch\s*\(|XMLHttpRequest|sendBeacon\s*\(|new\s+WebSocket\s*\(|\.ajax\s*\(", js.code):
            snip = js.text[max(0, m.start() - 350):m.start() + 450]
            if len(snip) > 900:
                snip = snip[:900]
            out.append({"file": js.rel, "line": js.line_of(m.start()), "why": "network call", "code": snip})
            budget -= len(snip)
            if budget < 8_000 or sum(1 for o in out if o["file"] == js.rel) >= 4:
                break
        if budget < 8_000:
            break
    # 2) evidence for high/critical rule hits
    sev = {r.id: r.severity for r in RULES}
    for rid, items in hits.items():
        if sev.get(rid) not in ("critical", "high", "medium"):
            continue
        for js, s, e in items[:2]:
            snip = js.text[max(0, s - 400):e + 1000][:1400]
            out.append({"file": js.rel, "line": js.line_of(s), "why": rid, "code": snip})
            budget -= len(snip)
        if budget < 0:
            break
    return out
