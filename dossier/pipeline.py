"""End-to-end orchestration: resolve -> fetch -> unpack -> analyse -> (LLM) -> score."""
from __future__ import annotations

import datetime as dt
import hashlib
import re
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from . import __version__
from .codescan import scan
from .config import LLMConfig
from .fetch import FetchError, Target, chrome_store_url, download_package, edge_store_url, fetch_store_metadata, resolve_target
from .knowledge import registrable_domain
from .llm import apply_triage, run_llm
from .manifest import analyze_manifest, build_permissions, icon_data_uri, load_manifest, resolve_i18n
from .models import AnalysisResult, ExtensionInfo
from .ownership import ownership_findings, publisher_history
from .threatintel import check as check_intel, intel_findings
from .reputation import reputation_findings, web_reputation
from .scoring import assign_ids, compute_scores, endpoint_findings, publisher_findings
from .unpack import extract_package, find_manifest_root

Log = Callable[[str], None]


def _domain_of(url: str) -> str:
    m = re.match(r"^[a-z]+://([^/:?#]+)", url or "", re.I)
    return registrable_domain(m.group(1)) if m else ""


_CODE_HOSTS = ("github.com", "gitlab.com", "codeberg.org", "sr.ht", "bitbucket.org")


def score_context(r: AnalysisResult) -> dict:
    """Facts the scorer uses for trust credits (see scoring.trust_credits)."""
    st = r.info.store or {}
    ctx: dict = {}
    if any(f.rule == "pub.history_stable" for f in r.findings):
        tl = (r.ownership or {}).get("timeline") or []
        try:
            first = dt.date.fromisoformat(tl[0]["date"][:10])
            ctx["stable_publisher_years"] = (dt.date.today() - first).days / 365.25
        except (IndexError, KeyError, ValueError):
            pass
    ctx["recommended"] = "recommended" in (st.get("badges") or [])
    users = st.get("users") if isinstance(st.get("users"), int) else 0
    ctx["users"] = users
    ctx["big_user_base"] = users >= (100_000 if r.info.browser == "firefox" else 1_000_000)
    urls = " ".join(str(x) for x in (st.get("publisher_url"), st.get("privacy_url"), r.info.homepage) if x).lower()
    rep = r.reputation or {}
    ctx["open_source"] = (any(h in urls for h in _CODE_HOSTS)
                          or bool(st.get("license") and st.get("license") not in ("all-rights-reserved", "other"))
                          or any("open source" in c.get("claim", "").lower() or "open-source" in c.get("claim", "").lower()
                                 for c in rep.get("reassurances") or []))
    ctx["clean_reputation"] = (bool(rep) and not rep.get("error") and rep.get("verdict") != "serious_concerns"
                               and not any(c.get("severity") in ("high", "medium") for c in rep.get("concerns") or []))
    return ctx


def _result(fut, default):
    if fut is None:
        return default
    try:
        return fut.result(timeout=240) or default
    except Exception as e:  # noqa: BLE001 - lookups are best-effort
        return {"error": f"lookup failed: {e}"} if isinstance(default, dict) else default


def _as_chrome(t: Target) -> Target:
    return Target("store", "chrome", t.ext_id, store_url=chrome_store_url(t.ext_id), raw=t.ext_id)


class LocalReadError(OSError):
    pass


def copy_readable(src: Path, dest: Path) -> tuple[Path, list[str]]:
    """Copy an unpacked extension to a private temp folder, skipping files that can't be read.

    Raises LocalReadError if manifest.json itself is unreadable (nothing useful can be analysed).
    """
    skipped: list[str] = []
    for p in src.rglob("*"):
        try:
            if not p.is_file() or p.is_symlink():
                continue
            rel = p.relative_to(src)
            data = p.read_bytes()
        except OSError:
            skipped.append(str(p.relative_to(src)))
            continue
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
    if not (dest / "manifest.json").is_file():
        raise LocalReadError(f"manifest.json unreadable ({len(skipped)} files locked)")
    return dest, skipped


def tree_hash(root: Path) -> str:
    """Content hash of an unpacked extension (store-added _metadata excluded) so folders can be change-tracked."""
    h = hashlib.sha256()
    for p in sorted(x for x in root.rglob("*") if x.is_file() and "_metadata" not in x.relative_to(root).parts):
        h.update(p.relative_to(root).as_posix().encode() + b"\0" + hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


def analyze(raw_target: str, *, browser: str | None = None, llm: LLMConfig | None = None,
            keep_dir: Path | None = None, log: Log = print,
            store_lookup: tuple[str, str] | None = None, context: dict | None = None,
            archive: bool = True, web: bool = True, intel: bool = True,
            intel_refresh: bool = False) -> AnalysisResult:
    """Analyse one extension.

    store_lookup: (store, id) to fetch store reputation for a *local* package, e.g. an installed extension.
    context:      free-form facts shown in the report header (browser profile, enabled state, ...).
    archive:      look up publisher history in archived store listings (web.archive.org).
    web:          ask the AI provider to search the web for reputation reports (OpenAI only).
    intel:        check public known-malicious extension lists (cached locally).
    """
    t: Target = resolve_target(raw_target, browser)
    info = ExtensionInfo(source=raw_target, browser=t.browser, ext_id=t.ext_id, store_url=t.store_url,
                         context=dict(context or {}))
    lookup: Target | None = t if t.kind == "store" else None
    if store_lookup and t.kind != "store":
        sb, sid = store_lookup
        url = {"chrome": chrome_store_url(sid), "edge": edge_store_url(sid),
               "firefox": f"https://addons.mozilla.org/firefox/addon/{sid}/"}[sb]
        lookup = Target("store", sb, sid, store_url=url, raw=sid)
        info.browser, info.ext_id, info.store_url = sb, sid, url
    work = Path(tempfile.mkdtemp(prefix="dossier_"))
    unreadable: list[str] = []
    fell_back = False
    try:
        if t.kind in ("dir", "file"):
            # Installed copies live in browser profiles that security software (or a sandbox) may lock. Copy what we
            # can read; if the essentials are unreadable, fall back to the store's copy of the same extension.
            try:
                if t.kind == "dir":
                    root, unreadable = copy_readable(find_manifest_root(t.path), work / "local")
                else:
                    t.path.read_bytes()[:1]
            except (PermissionError, LocalReadError, OSError) as e:
                if not lookup:
                    raise
                why = "permission denied" if isinstance(e, PermissionError) or "denied" in str(e).lower() else str(e)
                log(f"  installed copy unreadable ({why}); analysing the {lookup.browser} store copy instead")
                info.context["Analysed copy"] = ("store version (installed copy is read-protected, usually by "
                                                 "antivirus or browser-profile protection)")
                t, fell_back = lookup, True
        if t.kind == "dir":
            info.sha256 = tree_hash(root)
            if unreadable:
                info.context["Unreadable files"] = f"{len(unreadable)} skipped (locked or access denied)"
        else:
            if t.kind == "store":
                log(f"Downloading {t.browser} extension {t.ext_id} ...")
                try:
                    try:
                        data = download_package(t)
                    except FetchError:
                        if not (fell_back and t.browser == "edge"):
                            raise
                        # Edge users often install from the Chrome Web Store: try the same ID there.
                        t = lookup = _as_chrome(t)
                        info.browser, info.store_url = "chrome", t.store_url
                        data = download_package(t)
                except FetchError as e:
                    if not fell_back:
                        raise
                    raise FetchError(
                        "the installed copy can't be read (access denied, usually antivirus or browser-profile "
                        "protection) and the store has no downloadable copy (unlisted, removed, or a built-in "
                        f"component). Copy the folder somewhere readable and analyse that, or allow access. ({e})") from e
            else:
                data = t.path.read_bytes()
            info.sha256 = hashlib.sha256(data).hexdigest()
            info.package_size = len(data)
            dest = work / "pkg"
            st = extract_package(data, dest)
            if st["skipped"]:
                log(f"  skipped {len(st['skipped'])} unsafe archive entries")
            root = find_manifest_root(dest)
            if keep_dir:
                keep_dir.mkdir(parents=True, exist_ok=True)
                shutil.copytree(root, keep_dir, dirs_exist_ok=True)
                log(f"  unpacked copy kept at {keep_dir}")

        manifest = load_manifest(root)
        info.name = resolve_i18n(root, manifest, manifest.get("name", "")) or "(unnamed)"
        info.description = resolve_i18n(root, manifest, manifest.get("description", ""))
        info.version = str(manifest.get("version", ""))
        info.manifest_version = manifest.get("manifest_version")
        info.homepage = manifest.get("homepage_url") or ""
        a = manifest.get("author")
        info.author = a.get("email", "") if isinstance(a, dict) else (a or "")
        info.icon_data_uri = icon_data_uri(root, manifest)
        gecko = (manifest.get("browser_specific_settings") or manifest.get("applications") or {}).get("gecko") or {}
        if not info.ext_id and gecko.get("id"):
            info.ext_id = gecko["id"]
        if t.browser == "unknown":
            info.browser = "firefox" if gecko else "chrome"

        if lookup:
            log("Fetching store metadata ...")
            info.store = fetch_store_metadata(lookup)
            if lookup.browser == "edge" and info.store.get("removed"):
                # Not on Edge Add-ons: an Edge install from the Chrome Web Store is common, so check there before
                # calling it removed.
                chrome_meta = fetch_store_metadata(_as_chrome(lookup))
                if not chrome_meta.get("removed") and not chrome_meta.get("error"):
                    lookup = _as_chrome(lookup)
                    info.store, info.store_url = chrome_meta, lookup.store_url
                    info.context["Installed from"] = "Chrome Web Store (into Edge)"

        first_party = {d for d in (_domain_of(info.homepage), _domain_of(info.store.get("publisher_url", "")),
                                   _domain_of(manifest.get("update_url", ""))) if d}
        first_party -= {"github.com", "google.com", "mozilla.org", "microsoft.com", "githubusercontent.com"}
        # The publisher's own GitHub org (e.g. raw.githubusercontent.com/darkreader/...) is first-party, not a paste site.
        tokens = {d.split(".")[0] for d in first_party} | {info.name, info.store.get("publisher", ""), info.author}
        first_party |= {"gh:" + re.sub(r"[^a-z0-9]", "", t.lower()) for t in tokens if t and len(t) > 2}

        # Slow network lookups run in the background while the code is scanned.
        pool = ThreadPoolExecutor(max_workers=3)
        fut_hist = fut_rep = fut_intel = None
        if intel and info.ext_id:
            fut_intel = pool.submit(check_intel, info.browser, info.ext_id, info.sha256,
                                    info.store.get("guid") or gecko.get("id", ""), intel_refresh,
                                    version=info.version)
        if lookup and archive and info.browser in ("chrome", "firefox") and not info.store.get("removed"):
            slug = info.store.get("slug") or ("" if info.browser == "chrome" else lookup.ext_id)
            fut_hist = pool.submit(publisher_history, info.browser, info.ext_id, slug, log)
        if lookup and web and llm and llm.enabled and not llm.base_url:
            log("Searching the web for reputation reports ...")
            fut_rep = pool.submit(web_reputation, llm, info)

        log("Analysing manifest and code ...")
        perms = build_permissions(manifest)
        findings = analyze_manifest(manifest, perms)
        cs = scan(root, manifest, first_party)
        findings += cs.findings
        findings += endpoint_findings(cs.endpoints)
        pub, good = publisher_findings(info.store, sideloaded=lookup is None, browser=info.browser,
                                       local_version=info.version if t.kind != "store" else "", ext_id=info.ext_id)
        findings += pub
        hist = _result(fut_hist, {})
        intel_res = _result(fut_intel, {})
        findings += intel_findings(intel_res)
        rep = _result(fut_rep, {})
        pool.shutdown(wait=False)
        if hist:
            st = info.store
            findings += ownership_findings(hist, {"publisher": st.get("publisher", ""), "email": st.get("support_email", ""),
                                                  "website": st.get("publisher_url", "")})
        if rep and not rep.get("error"):
            findings += reputation_findings(rep)
        elif rep.get("error"):
            log("  " + rep["error"])
        info.file_count = cs.stats.get("files", 0)
        info.js_bytes = cs.stats.get("js_bytes", 0)
        assign_ids(findings)

        result = AnalysisResult(
            info=info, manifest=manifest, permissions=perms, findings=findings, endpoints=cs.endpoints,
            libraries=cs.libraries, noise=dict(cs.noise), file_stats={**cs.stats, "trust_signals": good},
            generated_at=dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z"), tool_version=__version__,
            ownership=hist, reputation=rep, intel=intel_res,
        )

        if llm and llm.enabled:
            log(f"Running LLM analysis via {llm.provider_label} ({llm.model}) ...")
            result.llm = run_llm(llm, result, cs.snippets_for_llm)
            if result.llm.get("error"):
                log("  " + result.llm["error"])
            else:
                apply_triage(result)
        scores = compute_scores(result.findings, score_context(result))
        result.score = scores["overall"]
        result.verdict = scores["verdict"]
        result.file_stats["scores"] = scores
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)
