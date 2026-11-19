"""Change tracking between two audits of the same extension.

Silent updates are how good extensions turn bad (sold to a new owner, new SDK bolted on). Every audit
saves a compact snapshot under <out>/history/; the next audit of the same extension is compared to the
most recent earlier snapshot, and the report opens with what changed.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .models import SEVERITY_RANK, AnalysisResult


def snapshot(r: AnalysisResult) -> dict:
    """Small, stable summary of an audit (what we diff against later)."""
    m = r.manifest
    cs = sorted({x for c in m.get("content_scripts") or [] if isinstance(c, dict) for x in c.get("matches") or []})
    return {
        "browser": r.info.browser, "ext_id": r.info.ext_id, "name": r.info.name, "version": r.info.version,
        "sha256": r.info.sha256, "generated_at": r.generated_at, "score": r.score, "verdict": r.verdict,
        "permissions": sorted(p.name for p in r.permissions if p.kind == "api"),
        "host_permissions": sorted(p.name for p in r.permissions if p.kind == "host"),
        "optional": sorted(p.name for p in r.permissions if p.kind.startswith("optional")),
        "content_script_matches": cs,
        "csp": json.dumps(m.get("content_security_policy"), sort_keys=True) if m.get("content_security_policy") else "",
        "update_url": m.get("update_url") or "",
        "endpoints": sorted(e.host for e in r.endpoints if e.request_context and not e.in_library_only),
        "trackers": sorted(e.host for e in r.endpoints if e.category in
                           ("analytics", "advertising", "session_recording", "affiliate", "telemetry", "remote_config")),
        "findings": {f.rule: {"title": f.title, "severity": f.severity} for f in r.findings},
        "publisher": (r.info.store or {}).get("publisher") or r.info.author or "",
        "publisher_url": (r.info.store or {}).get("publisher_url") or "",
    }


def _key(browser: str, ext_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9@._-]+", "_", f"{browser}_{ext_id}")


def history_path(out_dir: Path, r: AnalysisResult) -> Path:
    v = re.sub(r"[^A-Za-z0-9._-]+", "_", r.info.version or "unknown")
    h = (r.info.sha256 or "")[:8]
    return out_dir / "history" / f"{_key(r.info.browser, r.info.ext_id or r.info.name)}__{v}{'_' + h if h else ''}.json"


def find_previous(out_dir: Path, r: AnalysisResult) -> dict | None:
    """Most recent saved snapshot of the same extension that is not this exact package."""
    hdir = out_dir / "history"
    if not hdir.is_dir():
        return None
    prefix = _key(r.info.browser, r.info.ext_id or r.info.name) + "__"
    cands = []
    for p in hdir.glob(prefix + "*.json"):
        try:
            snap = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        same_pkg = snap.get("sha256") and snap.get("sha256") == r.info.sha256
        if snap.get("version") == r.info.version and (same_pkg or not r.info.sha256):
            continue
        cands.append((p.stat().st_mtime, snap))
    return max(cands, key=lambda x: x[0])[1] if cands else None


def load_baseline(path: Path) -> dict:
    d = json.loads(path.read_text(encoding="utf-8"))
    if "findings" in d and isinstance(d.get("findings"), list):   # a full --json export, not a snapshot
        raise ValueError("Pass a history snapshot (reports/history/*.json), not a full --json export.")
    return d


def save_snapshot(out_dir: Path, r: AnalysisResult) -> Path:
    p = history_path(out_dir, r)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(snapshot(r), indent=1), encoding="utf-8")
    return p


def compare(old: dict, new: dict) -> dict:
    def delta(k):
        a, b = set(old.get(k) or []), set(new.get(k) or [])
        return sorted(b - a), sorted(a - b)

    ch: dict = {"from_version": old.get("version"), "to_version": new.get("version"),
                "from_date": old.get("generated_at"), "score_before": old.get("score"), "score_after": new.get("score"),
                "verdict_before": old.get("verdict"), "verdict_after": new.get("verdict"), "items": []}

    def add(sev, text):
        ch["items"].append({"severity": sev, "text": text})

    if (old.get("version") == new.get("version") and old.get("sha256") and new.get("sha256")
            and old["sha256"] != new["sha256"]):
        add("high", "Same version number but different package contents. Legitimate releases bump the version.")
    if old.get("publisher") and new.get("publisher") and old["publisher"] != new["publisher"]:
        add("high", f"Publisher changed from '{old['publisher']}' to '{new['publisher']}'. Ownership transfers are the most "
                    "common way trusted extensions turn malicious.")
    if old.get("publisher_url") and new.get("publisher_url") and old["publisher_url"] != new["publisher_url"]:
        add("medium", f"Publisher website changed: {old['publisher_url']} → {new['publisher_url']}")
    added, removed = delta("permissions")
    if added:
        add("high", "New permissions: " + ", ".join(added))
    if removed:
        add("info", "Permissions dropped: " + ", ".join(removed))
    added, removed = delta("host_permissions")
    if added:
        add("high", "New site access: " + ", ".join(added))
    if removed:
        add("info", "Site access dropped: " + ", ".join(removed))
    added, _ = delta("content_script_matches")
    if added:
        add("medium", "Content scripts now also run on: " + ", ".join(added[:10]))
    added, _ = delta("optional")
    if added:
        add("low", "New optional permissions it can request later: " + ", ".join(added))
    if old.get("update_url", "") != new.get("update_url", ""):
        add("high", f"Update URL changed: '{old.get('update_url') or 'store'}' → '{new.get('update_url') or 'store'}'")
    if old.get("csp", "") != new.get("csp", ""):
        add("medium", "Content Security Policy changed.")
    added, _ = delta("trackers")
    if added:
        add("high", "New tracking / analytics hosts: " + ", ".join(added))
    added, removed = delta("endpoints")
    if added:
        add("medium", "New servers contacted: " + ", ".join(added[:15]) + (" …" if len(added) > 15 else ""))
    if removed:
        add("info", "No longer contacts: " + ", ".join(removed[:15]))
    of, nf = old.get("findings") or {}, new.get("findings") or {}
    for rule in sorted(set(nf) - set(of), key=lambda r: SEVERITY_RANK.get(nf[r]["severity"], 9)):
        if nf[rule]["severity"] in ("critical", "high", "medium"):
            add(nf[rule]["severity"], f"New finding: {nf[rule]['title']}")
    for rule in sorted(set(of) - set(nf)):
        if of[rule]["severity"] in ("critical", "high", "medium"):
            add("info", f"Resolved: {of[rule]['title']}")
    ch["items"].sort(key=lambda i: SEVERITY_RANK.get(i["severity"], 9))
    return ch
