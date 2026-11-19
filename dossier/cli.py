"""Command-line interface."""
from __future__ import annotations

import argparse
import json
import re
import sys
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import __version__
from .config import ConfigError, default_init_path, llm_config, load_config, write_template
from .fetch import FetchError
from .unpack import UnpackError

EPILOG = """examples:
  dossier https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh
  dossier ddkjiahejlhfcafbddmgiahcphecmpfh --browser edge
  dossier https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/
  dossier ublock-origin --browser firefox
  dossier C:\\Downloads\\thing.crx  ./unpacked-folder  --no-llm
  dossier --installed                      # audit everything in your local browser profiles
  dossier --installed firefox,brave --no-llm
  dossier --init-config                    # create config.json for your API key / local model

tip (Windows): store links often contain "&" (e.g. ...?hl=en&pli=1). Wrap the link in double quotes,
  or just pass the 32-letter ID. Without quotes, cmd/PowerShell cut the link at the "&" and try to run
  the rest as a command ("'pli' is not recognized ...").
    dossier "https://chromewebstore.google.com/detail/name/ofaokhiedipichpaobibbnahnkdoiiah?hl=en&pli=1"
    dossier ofaokhiedipichpaobibbnahnkdoiiah
"""


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")[:60] or "extension"


VERDICT_LEVEL = {"Low": 0, "Moderate": 1, "High": 2, "Severe": 3}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="dossier",
        description="Dossier: OPSEC-focused risk analysis of Chrome / Edge / Firefox extensions. Produces a self-contained HTML report.",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", help="Store URL, extension ID, Firefox slug, .crx/.xpi/.zip file, or unpacked folder")
    ap.add_argument("-b", "--browser", choices=["chrome", "edge", "firefox"], help="Which store a bare ID/slug refers to (default: chrome)")
    ap.add_argument("--installed", nargs="?", const="all", metavar="BROWSERS",
                    help="Audit extensions installed in your local browser profiles. Optionally a comma list: "
                         "chrome,edge,brave,chromium,vivaldi,opera,firefox")
    ap.add_argument("--list-installed", action="store_true", help="Only list installed extensions, don't analyse")
    ap.add_argument("-o", "--out", type=Path, default=Path("reports"), help="Output directory (or .html file for a single target)")
    ap.add_argument("--json", action="store_true", help="Also write the full analysis as JSON next to the report")
    ap.add_argument("--baseline", type=Path, metavar="SNAPSHOT", help="Compare against this history snapshot instead of the latest one")
    ap.add_argument("--no-history", action="store_true", help="Don't save or compare history snapshots")
    ap.add_argument("--fail-on", choices=["moderate", "high", "severe"],
                    help="Exit with code 2 if any extension reaches this verdict (for scripts / CI)")
    ap.add_argument("--no-llm", action="store_true", help="Static analysis only; nothing leaves your machine except store requests")
    ap.add_argument("--no-archive", action="store_true",
                    help="Skip the publisher-history lookup in archived store listings (web.archive.org)")
    ap.add_argument("--no-web", action="store_true", help="Skip the AI web search for news and security reports about the extension")
    ap.add_argument("--no-intel", action="store_true", help="Skip the check against public known-malicious extension lists")
    ap.add_argument("--update-intel", action="store_true", help="Re-download the known-malicious lists now (normally once a day)")
    ap.add_argument("--config", type=Path, metavar="FILE", help="Use this config.json (API key, model, local model URL)")
    ap.add_argument("--init-config", nargs="?", const="", metavar="FILE",
                    help="Create a ready-to-fill config.json (next to Dossier by default) and exit")
    ap.add_argument("--model", help="LLM model name for this run (overrides config.json)")
    ap.add_argument("--base-url", help="OpenAI-compatible base URL for this run, e.g. http://localhost:11434/v1")
    ap.add_argument("--keep", type=Path, metavar="DIR", help="Keep a copy of the unpacked extension in DIR for manual review")
    ap.add_argument("--open", action="store_true", help="Open the report (or the summary for several) in your browser when done")
    ap.add_argument("-j", "--jobs", type=int, default=4, help="Extensions to analyse in parallel (default 4)")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--version", action="version", version=f"Dossier {__version__}")
    a = ap.parse_args(argv)

    if a.init_config is not None:
        try:
            p = write_template(Path(a.init_config) if a.init_config else default_init_path())
        except ConfigError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(f"Created {p.resolve()}")
        print("Open it in a text editor and paste your OpenAI key (or set a local model).")
        return 0
    try:
        file_cfg, cfg_path = load_config(a.config)
    except ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    from .diff import compare, find_previous, load_baseline, save_snapshot, snapshot
    from .installed import discover_all
    from .pipeline import analyze
    from .report import render_html
    from .summary import render_summary

    # ---- build the job list ---------------------------------------------------------------
    jobs: list[tuple[str, dict, str]] = []   # (target, analyze kwargs, file-name suffix)
    if a.installed or a.list_installed:
        wanted = None if (a.installed in (None, "all")) else {b.strip().lower() for b in a.installed.split(",")}
        found = discover_all(wanted)
        if not found:
            print("No installed extensions found in local browser profiles.", file=sys.stderr)
            return 1
        if a.list_installed:
            for x in found:
                state = {True: "on ", False: "off", None: " ? "}[x.enabled]
                print(f"{x.browser:8} {x.profile[:18]:18} {state} {(x.name or '?')[:40]:40} {x.version:12} {x.ext_id}")
            return 0
        for x in found:
            ctx = {"Installed in": f"{x.browser.capitalize()} · profile '{x.profile}'",
                   "State": {True: "enabled", False: "disabled", None: "unknown"}[x.enabled]}
            jobs.append((str(x.path), {"store_lookup": (x.store, x.ext_id), "context": ctx}, f"{x.browser}_{x.profile}"))
    jobs += [(t, {"browser": a.browser}, "") for t in a.targets]
    if not jobs:
        ap.error("give at least one target, or use --installed")

    cfg = llm_config(no_llm=a.no_llm, model=a.model, base_url=a.base_url, file_cfg=file_cfg, source=cfg_path)
    log = (lambda *_: None) if a.quiet else (lambda m: print(m, file=sys.stderr))
    if not a.no_llm and not cfg.enabled:
        where = f"Add your OpenAI key to {cfg_path}" if cfg_path else "Run `dossier --init-config` and add your OpenAI key"
        log(f"No AI key set - running static analysis only. {where} (or set a local model) to enable the AI analyst.")
    elif cfg.enabled:
        log(f"AI: {cfg.provider_label}, model {cfg.model}" + (f" (settings from {cfg_path})" if cfg_path else ""))

    archive = not a.no_archive and file_cfg.get("archive_lookup", True) is not False
    web = not a.no_web and file_cfg.get("web_reputation", True) is not False
    intel = not a.no_intel and file_cfg.get("threat_intel", True) is not False
    out_dir = a.out.parent if (a.out.suffix.lower() == ".html" and len(jobs) == 1) else a.out
    def work(i: int):
        tgt, kw, suffix = jobs[i]
        tag = f"[{i + 1}/{len(jobs)}] " if len(jobs) > 1 else ""
        keep = (a.keep / _slug(suffix + "_" + Path(tgt).name if suffix else tgt)) if a.keep and len(jobs) > 1 else a.keep
        try:
            return analyze(tgt, llm=cfg if cfg.enabled else None, keep_dir=keep,
                           log=lambda m: log(tag + m.strip()), archive=archive, web=web,
                           intel=intel, intel_refresh=a.update_intel, **kw)
        except (FetchError, UnpackError, OSError, ValueError) as e:
            return e

    # Downloads and LLM calls are I/O bound, so several extensions are analysed at once.
    with ThreadPoolExecutor(max_workers=max(1, min(a.jobs, len(jobs)))) as pool:
        results = list(pool.map(work, range(len(jobs))))

    rc, worst, rows = 0, -1, []
    for (tgt, kw, suffix), res in zip(jobs, results):
        if isinstance(res, Exception):
            print(f"error: {tgt}: {res}", file=sys.stderr)
            rows.append({"error": str(res), "target": tgt})
            rc = 1
            continue

        # ---- change tracking ----
        if not a.no_history:
            try:
                prev = load_baseline(a.baseline) if a.baseline else find_previous(out_dir, res)
            except (OSError, ValueError) as e:
                print(f"warning: baseline not used: {e}", file=sys.stderr)
                prev = None
            if prev:
                res.changes = compare(prev, snapshot(res))
            save_snapshot(out_dir, res)

        if a.out.suffix.lower() == ".html" and len(jobs) == 1:
            out_html = a.out
        else:
            name = f"{_slug(res.info.name)}_{_slug(res.info.version)}_{_slug(suffix) if suffix else res.info.browser}.html"
            out_html = a.out / name
        out_html.parent.mkdir(parents=True, exist_ok=True)
        out_html.write_text(render_html(res), encoding="utf-8")
        if a.json:
            d = res.to_dict()
            d["info"].pop("icon_data_uri", None)
            out_html.with_suffix(".json").write_text(json.dumps(d, indent=2, default=str), encoding="utf-8")

        sc = res.file_stats.get("scores", {})
        worst = max(worst, VERDICT_LEVEL.get(res.verdict, 0))
        rows.append({"result": res, "file": out_html.name})
        top = [f for f in res.findings if f.severity in ("critical", "high") and f.llm_verdict != "likely_benign"]
        sys.stderr.flush()
        print(f"{res.info.name} {res.info.version} [{res.info.browser}]  ->  {res.verdict} risk "
              f"(overall {sc.get('overall')}/100, capability {sc.get('capability')}, behaviour {sc.get('behaviour')})")
        for f in top[:6]:
            print(f"  [{f.severity.upper():8}] {f.title}")
        notable = [c for c in (res.changes or {}).get("items", []) if c["severity"] in ("critical", "high")]
        if res.changes:
            print(f"  changed since {res.changes.get('from_version')}: {len(res.changes.get('items', []))} change(s)"
                  + (f", {len(notable)} important" if notable else ""))
        if res.llm.get("headline"):
            print(f"  AI: {res.llm['headline']}")
        print(f"  report: {out_html.resolve()}", flush=True)

    to_open = None
    if len(jobs) > 1:
        idx = out_dir / "index.html"
        idx.parent.mkdir(parents=True, exist_ok=True)
        idx.write_text(render_summary(rows, title="Installed extensions" if a.installed else "Extension audit"), encoding="utf-8")
        print(f"\nsummary: {idx.resolve()}")
        to_open = idx
    elif rows and "file" in rows[-1]:
        to_open = out_dir / rows[-1]["file"] if a.out.suffix.lower() != ".html" else a.out
    if a.open and to_open:
        webbrowser.open(to_open.resolve().as_uri())

    if a.fail_on and worst >= VERDICT_LEVEL[a.fail_on.capitalize()]:
        return 2
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
