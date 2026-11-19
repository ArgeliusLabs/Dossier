"""Manifest parsing and manifest-level risk analysis (capabilities, CSP, updates, exposure)."""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path

from .knowledge import ALL_URL_PATTERNS, PERMISSIONS, SENSITIVE_SITES, UNKNOWN_PERMISSION
from .models import Evidence, Finding, Permission

STORE_UPDATE_HOSTS = (
    "clients2.google.com", "update.googleapis.com", "edge.microsoft.com",
    "extensionwebstorebase", "addons.mozilla.org", "versioncheck.addons.mozilla.org",
)


def _strip_json_comments(text: str) -> str:
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1]); i += 2; continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True; out.append(c)
        elif text.startswith("//", i):
            j = text.find("\n", i); i = n if j < 0 else j; continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2); i = n if j < 0 else j + 2; continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def load_manifest(root: Path) -> dict:
    raw = (root / "manifest.json").read_bytes().decode("utf-8-sig", "replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return json.loads(_strip_json_comments(raw))


def resolve_i18n(root: Path, manifest: dict, value: str) -> str:
    if not isinstance(value, str):
        return ""
    m = re.fullmatch(r"__MSG_(\w+)__", value.strip())
    if not m:
        return value
    key = m.group(1).lower()
    default = manifest.get("default_locale") or "en"
    for loc in (default, "en", "en_US", "en_GB"):
        f = root / "_locales" / loc / "messages.json"
        if f.is_file():
            try:
                msgs = json.loads(_strip_json_comments(f.read_bytes().decode("utf-8-sig", "replace")))
            except Exception:  # noqa: BLE001
                continue
            for k, v in msgs.items():
                if k.lower() == key and isinstance(v, dict):
                    return v.get("message", value)
    return value


def icon_data_uri(root: Path, manifest: dict) -> str:
    icons = manifest.get("icons") or {}
    if not isinstance(icons, dict) or not icons:
        return ""
    try:
        best = sorted(icons.items(), key=lambda kv: abs(int(kv[0]) - 128))[0][1]
    except (ValueError, TypeError):
        best = next(iter(icons.values()))
    p = (root / str(best).lstrip("/")).resolve()
    if not str(p).startswith(str(root.resolve())) or not p.is_file() or p.stat().st_size > 512_000:
        return ""
    mime = {".png": "image/png", ".svg": "image/svg+xml", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
            ".gif": "image/gif", ".webp": "image/webp", ".ico": "image/x-icon"}.get(p.suffix.lower())
    if not mime or mime == "image/svg+xml":   # don't embed attacker-controlled SVG into the report
        return ""
    return f"data:{mime};base64,{base64.b64encode(p.read_bytes()).decode()}"


# ---------------------------------------------------------------- permissions --------

def _split_permissions(manifest: dict) -> tuple[list[str], list[str], list[str], list[str]]:
    mv = manifest.get("manifest_version", 2)
    api, hosts, opt_api, opt_hosts = [], [], [], []

    def is_host(p: str) -> bool:
        return p == "<all_urls>" or "://" in p or p.startswith("*")

    for p in manifest.get("permissions", []) or []:
        if not isinstance(p, str):
            continue
        (hosts if is_host(p) else api).append(p)
    for p in manifest.get("optional_permissions", []) or []:
        if isinstance(p, str):
            (opt_hosts if is_host(p) else opt_api).append(p)
    if mv >= 3:
        hosts += [h for h in manifest.get("host_permissions", []) or [] if isinstance(h, str)]
        opt_hosts += [h for h in manifest.get("optional_host_permissions", []) or [] if isinstance(h, str)]
    return api, hosts, opt_api, opt_hosts


def content_script_matches(manifest: dict) -> list[str]:
    out = []
    for cs in manifest.get("content_scripts", []) or []:
        if isinstance(cs, dict):
            out += [m for m in cs.get("matches", []) or [] if isinstance(m, str)]
    return out


def is_all_urls(pattern: str) -> bool:
    if pattern in ALL_URL_PATTERNS:
        return True
    m = re.match(r"^(\*|https?|wss?|file|ftp)://([^/]*)/", pattern + ("/" if pattern.count("/") < 3 else ""))
    return bool(m and m.group(2) in ("*", ""))


def _host_of(pattern: str) -> str:
    m = re.match(r"^[^:]+://([^/]*)", pattern)
    return (m.group(1) if m else pattern).lstrip("*.").lower()


def sensitive_sites_in(patterns: list[str]) -> list[str]:
    hits = []
    for p in patterns:
        h = _host_of(p)
        for site, label in SENSITIVE_SITES.items():
            if h == site or h.endswith("." + site) or site.endswith("." + h) and h.count(".") >= 1:
                hits.append(f"{label} ({p})")
                break
    return sorted(set(hits))


def build_permissions(manifest: dict) -> list[Permission]:
    api, hosts, opt_api, opt_hosts = _split_permissions(manifest)
    out: list[Permission] = []
    for kind, names in (("api", api), ("optional_api", opt_api)):
        for n in dict.fromkeys(names):
            sev, summ, ops = PERMISSIONS.get(n, UNKNOWN_PERMISSION)
            if kind == "optional_api":
                sev = _downgrade(sev)
            out.append(Permission(n, kind, sev, summ, ops))
    for kind, names in (("host", hosts), ("optional_host", opt_hosts)):
        for n in dict.fromkeys(names):
            if is_all_urls(n):
                sev, summ = "high", "Read and change data on every website you visit."
            elif n.startswith("file:"):
                sev, summ = "high", "Read local files opened in the browser (if you allow file access)."
            elif _host_of(n).count(".") == 0 and "*" in n:
                sev, summ = "high", "Very broad wildcard host pattern."
            else:
                sev, summ = "low", f"Read and change data on {_host_of(n) or n}."
            if kind == "optional_host":
                sev = _downgrade(sev)
            out.append(Permission(n, kind, sev, summ))
    return out


def _downgrade(sev: str) -> str:
    order = ["critical", "high", "medium", "low", "info"]
    return order[min(order.index(sev) + 1, len(order) - 1)]


# ---------------------------------------------------------------- findings -----------

def analyze_manifest(manifest: dict, permissions: list[Permission]) -> list[Finding]:
    f: list[Finding] = []
    mv = manifest.get("manifest_version")
    api = {p.name for p in permissions if p.kind == "api"}
    hosts = [p.name for p in permissions if p.kind == "host"]
    cs_matches = content_script_matches(manifest)
    all_hosts = any(is_all_urls(h) for h in hosts)
    all_cs = any(is_all_urls(m) for m in cs_matches)
    ev = lambda s: [Evidence("manifest.json", None, s)]  # noqa: E731

    # --- Broad site access -----------------------------------------------------------
    if all_hosts or all_cs:
        where = "host permissions" if all_hosts else "content scripts that run on every site"
        f.append(Finding(
            "host.all_urls", "host_access", "high",
            "Can read and change everything on every website",
            f"Through its {where}, this extension can see the full content of every page you load "
            "(including logged-in pages such as webmail, social media and internal tools), read what you type, "
            "and modify what you see.",
            ev(", ".join(sorted(set([h for h in hosts if is_all_urls(h)] + [m for m in cs_matches if is_all_urls(m)])))),
            opsec="Treat this as 'the publisher can see all your browsing'. For investigation profiles, prefer "
                  "extensions that use activeTab (access only when clicked) or a short list of specific sites."))
    sens = sensitive_sites_in(hosts + cs_matches)
    if sens and not (all_hosts or all_cs):
        f.append(Finding("host.sensitive", "host_access", "medium",
                         "Targets specific sensitive sites",
                         "The extension asks for access to sites that hold accounts and private data: " + "; ".join(sens[:12]),
                         ev("; ".join(sens[:12])),
                         opsec="Make sure this matches the stated purpose. Unexplained access to mail, messaging or AI-chat "
                               "sites is a hallmark of data-harvesting extensions."))

    # --- Dangerous API combos ---------------------------------------------------------
    if "cookies" in api and (all_hosts or all_cs):
        f.append(Finding("combo.cookies_all", "permissions", "critical",
                         "Can read your login cookies for every site",
                         "With the cookies permission plus access to all sites, the extension can read session cookies, "
                         "which are effectively your logged-in sessions. Stolen session cookies allow account takeover "
                         "without your password or 2FA.",
                         ev("permissions: cookies + all-sites host access"),
                         opsec="If you run sock-puppet accounts in this profile, this extension can link or hijack them."))
    if ("webRequestBlocking" in api or "declarativeNetRequestWithHostAccess" in api) and all_hosts:
        f.append(Finding("combo.intercept_all", "permissions", "high",
                         "Can intercept and rewrite traffic on every site",
                         "It can modify requests and responses for all sites, e.g. remove security headers (CSP, X-Frame-Options), "
                         "redirect you, or inject content.",
                         ev("webRequestBlocking / declarativeNetRequestWithHostAccess + all sites")))
    if "scripting" in api and all_hosts:
        f.append(Finding("combo.scripting_all", "permissions", "high",
                         "Can inject code into any page on demand",
                         "The scripting permission with all-site access lets the extension run its code inside any page at any time, "
                         "not just pages it declared up front.",
                         ev("scripting + all-sites host access")))
    for p in permissions:
        if p.kind == "api" and p.severity in ("critical", "high") and p.name not in ("cookies", "webRequestBlocking"):
            f.append(Finding(f"perm.{p.name}", "permissions", p.severity,
                             f"Sensitive permission: {p.name}", p.summary, ev(f'"permissions": [... "{p.name}" ...]'),
                             opsec=p.opsec))
    if "cookies" in api and not (all_hosts or all_cs):
        f.append(Finding("perm.cookies", "permissions", "medium", "Sensitive permission: cookies",
                         PERMISSIONS["cookies"][1], ev('"cookies"'), opsec=PERMISSIONS["cookies"][2]))
    names = [n for n in ("webNavigation", "tabs") if n in api]
    if names and "history" not in api and not (all_hosts or all_cs):
        f.append(Finding("perm.browsing_activity", "permissions", "medium",
                         "Can see which sites you visit",
                         "Permissions " + ", ".join(names) + " let it observe the URLs you open, i.e. a live record of your browsing.",
                         ev(", ".join(names))))
    opt = [p for p in permissions if p.kind in ("optional_api", "optional_host") and p.severity in ("critical", "high", "medium")]
    if opt:
        f.append(Finding("perm.optional", "permissions", "low",
                         "Can ask for more access later",
                         "These optional permissions are not granted at install but the extension can prompt for them at runtime: "
                         + ", ".join(p.name for p in opt[:15]),
                         ev(", ".join(p.name for p in opt[:15])),
                         opsec="Decline runtime permission prompts you don't understand."))

    # --- Content scripts --------------------------------------------------------------
    flags, files, main_world = [], [], False
    for cs in manifest.get("content_scripts", []) or []:
        if not isinstance(cs, dict) or not any(is_all_urls(m) for m in cs.get("matches", []) or []):
            continue
        before = len(flags)
        if cs.get("all_frames"):
            flags.append("runs inside every iframe (including embedded third-party frames)")
        if cs.get("run_at") == "document_start":
            flags.append("runs before the page's own code (document_start)")
        if cs.get("world") == "MAIN":
            main_world = True
            flags.append("runs in the page's own JavaScript context (MAIN world), sharing objects with the site")
        if cs.get("match_about_blank") or cs.get("match_origin_as_fallback"):
            flags.append("also injects into about:blank/blob frames")
        if len(flags) > before:
            files += [str(j) for j in (cs.get("js") or [])[:3]]
    if flags:
        f.append(Finding("cs.aggressive", "host_access", "high" if main_world else "medium",
                         "Content scripts injected aggressively on all sites",
                         "Its page scripts " + "; ".join(dict.fromkeys(flags)) + ". This maximises what it can observe and modify.",
                         ev(", ".join(files[:6]) or "content_scripts")))

    # --- Remote code / CSP --------------------------------------------------------------
    f += analyze_csp(manifest)
    is_firefox = bool((manifest.get("browser_specific_settings") or manifest.get("applications") or {}).get("gecko"))
    if mv == 2:
        f.append(Finding("mv.v2", "remote_code", "low" if is_firefox else "medium",
                         "Uses legacy Manifest V2",
                         "Manifest V2 extensions are allowed to load and run remotely hosted code and use blocking webRequest. "
                         "Chrome has phased MV2 out; on Firefox it is still supported. Code you review today may not be what runs tomorrow.",
                         ev('"manifest_version": 2')))
    bg = manifest.get("background") or {}
    if isinstance(bg, dict) and bg.get("persistent") is True:
        f.append(Finding("bg.persistent", "behavior", "low", "Always-running background page",
                         "A persistent background page runs for the entire browser session, which is needed for constant monitoring.",
                         ev('"persistent": true')))

    # --- Updates ---------------------------------------------------------------------
    upd = manifest.get("update_url") or ((manifest.get("browser_specific_settings") or {}).get("gecko") or {}).get("update_url")
    if upd and not any(h in upd for h in STORE_UPDATE_HOSTS):
        f.append(Finding("update.offstore", "supply_chain", "high",
                         "Updates come from outside the official store",
                         f"The manifest points updates at {upd}. Updates from this server bypass store review entirely: "
                         "the publisher (or whoever controls that server) can push any code at any time.",
                         ev(f'"update_url": "{upd}"'),
                         opsec="Self-hosted updates are typical of side-loaded/enterprise tools and of malware. Pin and re-audit."))

    # --- Exposure to websites -----------------------------------------------------------
    ec = manifest.get("externally_connectable")
    if isinstance(ec, dict):
        matches = ec.get("matches") or []
        ids = ec.get("ids") or []
        broad = [m for m in matches if is_all_urls(m) or re.match(r"^\*://\*\.[a-z]+/\*$", m) or "*" == _host_of(m)]
        if broad or "*" in ids:
            f.append(Finding("ext.connectable_broad", "exposure", "high",
                             "Any website or extension can send it commands",
                             "externally_connectable allows broad message access: " + ", ".join((broad + (["any extension"] if "*" in ids else []))[:6])
                             + ". Websites can talk directly to the extension's privileged code.",
                             ev(json.dumps(ec)[:300])))
        elif matches:
            f.append(Finding("ext.connectable", "exposure", "low",
                             "Specific websites can talk to the extension",
                             "These sites can send messages to the extension (normally the publisher's own web app): "
                             + ", ".join(matches[:8]),
                             ev(", ".join(matches[:8])),
                             opsec="Those sites can also confirm the extension is installed, i.e. detect you."))
    f += analyze_web_accessible(manifest)

    # --- Behaviour overrides -----------------------------------------------------------
    cso = manifest.get("chrome_settings_overrides") or {}
    if cso.get("search_provider"):
        sp = cso["search_provider"]
        f.append(Finding("override.search", "behavior", "medium", "Replaces your search engine",
                         f"Changes the default search provider to {sp.get('search_url', '?')}. Search-hijacking is a common way to "
                         "monetise (and log) your queries.",
                         ev(json.dumps(sp)[:300]),
                         opsec="Every search query you type in the address bar goes to this provider."))
    if cso.get("homepage") or cso.get("startup_pages"):
        f.append(Finding("override.homepage", "behavior", "low", "Changes homepage/startup pages",
                         "Overrides homepage or startup pages.", ev(json.dumps(cso)[:300])))
    if (manifest.get("chrome_url_overrides") or {}).get("newtab"):
        f.append(Finding("override.newtab", "behavior", "info", "Replaces the New Tab page",
                         "Every new tab loads the extension's page, which can include its own analytics.",
                         ev("chrome_url_overrides.newtab")))
    if manifest.get("incognito") == "spanning" and (all_hosts or all_cs):
        pass  # normal default; not worth a finding
    if manifest.get("oauth2"):
        f.append(Finding("identity.oauth2", "permissions", "low", "Uses Google account OAuth",
                         "Declares an OAuth client and scopes: " + ", ".join((manifest["oauth2"].get("scopes") or [])[:6]),
                         ev(json.dumps(manifest["oauth2"])[:300])))

    # --- Firefox data collection declaration ------------------------------------------
    gecko = (manifest.get("browser_specific_settings") or {}).get("gecko") or {}
    dcp = gecko.get("data_collection_permissions")
    if isinstance(dcp, dict):
        req = [x for x in dcp.get("required", []) if x != "none"]
        if req:
            f.append(Finding("ff.data_collection", "data_collection", "medium",
                             "Declares that it collects your data",
                             "In its Firefox data-collection declaration, the developer states it collects: " + ", ".join(req) + ".",
                             ev(json.dumps(dcp))))
    return f


def parse_csp(policy: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in policy.split(";"):
        toks = part.strip().split()
        if toks:
            out[toks[0].lower()] = toks[1:]
    return out


def analyze_csp(manifest: dict) -> list[Finding]:
    csp = manifest.get("content_security_policy")
    policies: list[tuple[str, str]] = []
    if isinstance(csp, str):
        policies.append(("extension pages", csp))
    elif isinstance(csp, dict):
        for k, v in csp.items():
            if isinstance(v, str):
                policies.append((k.replace("_", " "), v))
    out: list[Finding] = []
    for where, pol in policies:
        d = parse_csp(pol)
        script = d.get("script-src") or d.get("default-src") or []
        remote = [s for s in script if re.match(r"^(https?:|wss?:|\*|//)", s) or (("." in s) and not s.startswith("'"))]
        if "'unsafe-eval'" in script:
            out.append(Finding("csp.unsafe_eval", "remote_code", "high",
                               "Allows eval() of arbitrary strings",
                               f"The CSP for {where} includes 'unsafe-eval', permitting code to be built from strings at runtime "
                               "(e.g. code downloaded from a server).", [Evidence("manifest.json", None, pol[:300])]))
        if remote:
            out.append(Finding("csp.remote_script", "remote_code", "high",
                               "Allows loading scripts from remote servers",
                               f"The CSP for {where} permits scripts from: {', '.join(remote[:6])}. Code from these hosts runs with "
                               "the extension's full privileges and can change at any time without a store update.",
                               [Evidence("manifest.json", None, pol[:300])],
                               opsec="This defeats store review: the reviewed package is not the code you run."))
    return out


def analyze_web_accessible(manifest: dict) -> list[Finding]:
    war = manifest.get("web_accessible_resources") or []
    exposed: list[str] = []
    dynamic = True
    if war and isinstance(war[0], str):                 # MV2: accessible to every site
        exposed = list(war)
        dynamic = False
    else:
        for entry in war:
            if isinstance(entry, dict) and any(is_all_urls(m) for m in entry.get("matches", []) or []):
                exposed += entry.get("resources", []) or []
                if not entry.get("use_dynamic_url"):
                    dynamic = False
    if not exposed or dynamic:
        return []
    return [Finding("fp.war", "fingerprinting", "low",
                    "Websites can detect that you have this extension installed",
                    "Files are exposed to every website at a fixed extension URL. Any site can probe for them and learn that this "
                    "extension is installed, which adds to your browser fingerprint and can reveal your tooling.",
                    [Evidence("manifest.json", None, ", ".join(exposed[:8]))],
                    opsec="Investigative tooling detected by a target's site is an OPSEC leak. Detection is passive and silent.")]
