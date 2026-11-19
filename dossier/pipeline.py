"""End-to-end orchestration: resolve -> fetch -> unpack -> analyse -> (LLM) -> score."""
from __future__ import annotations

import datetime as dt
import hashlib
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from . import __version__
from .codescan import scan
from .config import LLMConfig
from .fetch import Target, chrome_store_url, download_package, edge_store_url, fetch_store_metadata, resolve_target
from .knowledge import registrable_domain
from .llm import apply_triage, run_llm
from .manifest import analyze_manifest, build_permissions, icon_data_uri, load_manifest, resolve_i18n
from .models import AnalysisResult, ExtensionInfo
from .ownership import ownership_findings, publisher_history
from .reputation import reputation_findings, web_reputation
from .scoring import assign_ids, compute_scores, endpoint_findings, publisher_findings
from .unpack import extract_package, find_manifest_root

Log = Callable[[str], None]


def _domain_of(url: str) -> str:
    import re
    m = re.match(r"^[a-z]+://([^/:?#]+)", url or "", re.I)
    return registrable_domain(m.group(1)) if m else ""


def _result(fut, default):
    if fut is None:
        return default
    try:
        return fut.result(timeout=240) or default
    except Exception as e:  # noqa: BLE001 - lookups are best-effort
        return {"error": f"lookup failed: {e}"} if isinstance(default, dict) else default


def tree_hash(root: Path) -> str:
    """Content hash of an unpacked extension (store-added _metadata excluded) so folders can be change-tracked."""
    h = hashlib.sha256()
    for p in sorted(x for x in root.rglob("*") if x.is_file() and "_metadata" not in x.relative_to(root).parts):
        h.update(p.relative_to(root).as_posix().encode() + b"\0" + hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


def analyze(raw_target: str, *, browser: str | None = None, llm: LLMConfig | None = None,
            keep_dir: Path | None = None, log: Log = print,
            store_lookup: tuple[str, str] | None = None, context: dict | None = None,
            archive: bool = True, web: bool = True) -> AnalysisResult:
    """Analyse one extension.

    store_lookup: (store, id) to fetch store reputation for a *local* package, e.g. an installed extension.
    context:      free-form facts shown in the report header (browser profile, enabled state, ...).
    archive:      look up publisher history in archived store listings (web.archive.org).
    web:          ask the AI provider to search the web for reputation reports (OpenAI only).
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
    try:
        if t.kind == "dir":
            root = find_manifest_root(t.path)
            info.sha256 = tree_hash(root)
        else:
            if t.kind == "store":
                log(f"Downloading {t.browser} extension {t.ext_id} ...")
                data = download_package(t)
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

        first_party = {d for d in (_domain_of(info.homepage), _domain_of(info.store.get("publisher_url", "")),
                                   _domain_of(manifest.get("update_url", ""))) if d}
        first_party -= {"github.com", "google.com", "mozilla.org", "microsoft.com", "githubusercontent.com"}

        # Slow network lookups run in the background while the code is scanned.
        pool = ThreadPoolExecutor(max_workers=2)
        fut_hist = fut_rep = None
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
                                       local_version=info.version if t.kind != "store" else "")
        findings += pub
        hist = _result(fut_hist, {})
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
            ownership=hist, reputation=rep,
        )

        if llm and llm.enabled:
            log(f"Running LLM analysis via {llm.provider_label} ({llm.model}) ...")
            result.llm = run_llm(llm, result, cs.snippets_for_llm)
            if result.llm.get("error"):
                log("  " + result.llm["error"])
            else:
                apply_triage(result)
        scores = compute_scores(result.findings)
        result.score = scores["overall"]
        result.verdict = scores["verdict"]
        result.file_stats["scores"] = scores
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)
