"""Known-bad extension lists: match the analysed extension's ID (and package hash) against public threat intel.

Sources (downloaded at runtime from the maintainers, cached locally, refreshed once a day):

  * The Privacy Commons Institute "chrome-mal-ids"  (github.com/The-Privacy-Commons-Institute/chrome-mal-ids)
    Curated, sourced list of malicious Chrome/Edge extension IDs with threat type and article links.
  * Malicious Extension Sentry                        (github.com/toborrm9/malicious_extension_sentry)
    Chrome/Edge extensions removed from the stores (malware, policy violations, unwanted software) or flagged
    as suspicious while still listed; updated daily, includes CRX hashes.
  * Mozilla add-on blocklist                          (addons.mozilla.org blocklist API + legacy Remote Settings)
    Firefox add-ons Mozilla has blocked, with the reason and bug link.

If a download fails, the last cached copy is used and the report says how old it is. Nothing about the
extension being checked is sent anywhere except for Firefox, where the add-on ID is looked up on AMO.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import threading
import time
import urllib.parse
from pathlib import Path

from .fetch import FetchError, _get
from .models import Evidence, Finding

MAX_AGE = 24 * 3600
CHROME_ID = re.compile(r"^[a-p]{32}$")

SOURCES = {
    "tpci": {
        "label": "Privacy Commons Institute chrome-mal-ids",
        "home": "https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids",
        "url": "https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/data/current-list-meta.csv",
    },
    "sentry": {
        "label": "Malicious Extension Sentry",
        "home": "https://github.com/toborrm9/malicious_extension_sentry",
        "url": "https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/malicious_extensions_detailed.csv",
    },
    "mozilla_legacy": {
        "label": "Mozilla add-on blocklist (legacy)",
        "home": "https://blocked.cdn.mozilla.net/",
        "url": "https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/addons/records",
    },
}
AMO_BLOCK_API = "https://addons.mozilla.org/api/v5/blocklist/block/{}/"


def cache_dir() -> Path:
    d = Path(os.environ.get("DOSSIER_CACHE_DIR") or Path.home() / ".dossier" / "cache")
    d.mkdir(parents=True, exist_ok=True)
    return d


# ------------------------------------------------------------------ parsing -------------

def _parse_tpci(raw: bytes) -> dict:
    out: dict = {}
    for r in csv.DictReader(io.StringIO(raw.decode("utf-8-sig", "replace"))):
        ext_id = (r.get("EXTID") or "").strip().lower()
        if not CHROME_ID.match(ext_id):
            continue
        out.setdefault(ext_id, []).append({
            "name": r.get("EXTID-NAME", "")[:120],
            "added": r.get("DATE-ADD") or r.get("DATE-DIS", ""),
            "confirmed": (r.get("CONFIRM-MAL") or "").strip() == "1",
            "threat": r.get("THREAT-TYPE", "")[:120],
            "ownership_transfer": (r.get("OWNERSHIP-TRANSFER") or "").strip() == "1",
            "notes": (r.get("NOTES") or "")[:400],
            "links": [u for u in (r.get("SOURCE"), r.get("ARTICLE")) if u and u.startswith("http")][:2],
        })
    return {"ids": out}


def _parse_sentry(raw: bytes) -> dict:
    ids: dict = {}
    hashes: dict = {}
    for r in csv.DictReader(io.StringIO(raw.decode("utf-8-sig", "replace"))):
        ext_id = (r.get("extension_id") or "").strip().lower()
        if not CHROME_ID.match(ext_id):
            continue
        src = r.get("source") or ""
        entry = {"name": (r.get("name") or "")[:120], "reason": (r.get("reason") or "")[:120],
                 "added": r.get("insert_date_fmt", ""), "store": r.get("store", ""), "version": r.get("version", ""),
                 "links": [src] if src.startswith("http") else [], "source_note": "" if src.startswith("http") else src}
        ids.setdefault(ext_id, []).append(entry)
        h = (r.get("sha256") or "").strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", h):
            hashes[h] = ext_id
    return {"ids": ids, "hashes": hashes}


def _parse_mozilla_legacy(raw: bytes) -> dict:
    exact, patterns = {}, []
    for r in json.loads(raw.decode("utf-8", "replace")).get("data", []):
        guid = r.get("guid") or ""
        det = r.get("details") or {}
        entry = {"name": det.get("name", "")[:120], "reason": (det.get("why") or "")[:300],
                 "links": [det["bug"]] if str(det.get("bug", "")).startswith("http") else [],
                 "added": time.strftime("%Y-%m-%d", time.gmtime((r.get("last_modified") or 0) / 1000))}
        if guid.startswith("/") and guid.endswith("/"):
            patterns.append([guid[1:-1], entry])
        elif guid:
            exact[guid.lower()] = entry
    return {"exact": exact, "patterns": patterns}


PARSERS = {"tpci": _parse_tpci, "sentry": _parse_sentry, "mozilla_legacy": _parse_mozilla_legacy}


# ------------------------------------------------------------------ cache ---------------

_LOCKS = {k: threading.Lock() for k in SOURCES}
_LOCKS["amo"] = threading.Lock()


def load_source(key: str, refresh: bool = False, offline: bool = False) -> tuple[dict, dict]:
    """Returns (data, status). status = {"label", "fetched", "stale", "error"}. Thread-safe (parallel jobs)."""
    with _LOCKS[key]:
        return _load_source(key, refresh, offline)


def _load_source(key: str, refresh: bool, offline: bool) -> tuple[dict, dict]:
    src = SOURCES[key]
    path = cache_dir() / f"intel-{key}.json"
    cached = None
    if path.is_file():
        try:
            cached = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            cached = None
    fresh = cached and time.time() - cached.get("fetched", 0) < MAX_AGE
    status = {"label": src["label"], "home": src["home"]}
    if cached and (fresh and not refresh or offline):
        return cached["data"], {**status, "fetched": cached["fetched"], "stale": not fresh}
    if offline:
        return {}, {**status, "error": "not downloaded yet (offline)"}
    try:
        data = PARSERS[key](_get(src["url"], limit=60 * 1024 * 1024))
        blob = {"fetched": time.time(), "data": data}
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(blob), encoding="utf-8")
        tmp.replace(path)
        return data, {**status, "fetched": blob["fetched"], "stale": False}
    except (FetchError, ValueError, OSError, KeyError) as e:
        if cached:
            return cached["data"], {**status, "fetched": cached["fetched"], "stale": True, "error": f"update failed: {e}"}
        return {}, {**status, "error": f"unavailable: {e}"}


def _amo_block(guid: str) -> dict | None:
    """Live lookup of one Firefox add-on ID on Mozilla's blocklist (cached for a day)."""
    with _LOCKS["amo"]:
        return _amo_block_locked(guid)


def _amo_block_locked(guid: str) -> dict | None:
    path = cache_dir() / "intel-amo-lookups.json"
    try:
        cache = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except (OSError, ValueError):
        cache = {}
    hit = cache.get(guid)
    if hit and time.time() - hit.get("t", 0) < MAX_AGE:
        return hit.get("block")
    try:
        block = json.loads(_get(AMO_BLOCK_API.format(urllib.parse.quote(guid, safe="")), accept="application/json"))
    except FetchError as e:
        if e.status != 404:
            return hit.get("block") if hit else None
        block = None
    except ValueError:
        block = None
    cache[guid] = {"t": time.time(), "block": block}
    try:
        path.write_text(json.dumps(cache), encoding="utf-8")
    except OSError:
        pass
    return block


# ------------------------------------------------------------------ matching ------------

def check(browser: str, ext_id: str, sha256: str = "", guid: str = "", refresh: bool = False,
          offline: bool = False) -> dict:
    """Returns {"hits": [...], "sources": [status...]}. Never raises."""
    hits, statuses = [], []
    ext_id = (ext_id or "").strip()
    if browser in ("chrome", "edge", "unknown") and (CHROME_ID.match(ext_id.lower()) or sha256):
        for key in ("tpci", "sentry"):
            data, st = load_source(key, refresh, offline)
            statuses.append(st)
            for e in (data.get("ids") or {}).get(ext_id.lower(), []):
                hits.append({"source": key, "label": st["label"], "home": st["home"], **e})
            if sha256 and (data.get("hashes") or {}).get(sha256.lower()) and not any(h["source"] == key for h in hits):
                other = data["hashes"][sha256.lower()]
                for e in data["ids"].get(other, []):
                    hits.append({"source": key, "label": st["label"], "home": st["home"], "hash_match": other, **e})
    gid = guid or (ext_id if browser == "firefox" else "")
    if gid and browser == "firefox":
        data, st = load_source("mozilla_legacy", refresh, offline)
        statuses.append(st)
        e = (data.get("exact") or {}).get(gid.lower())
        if not e:
            for pat, entry in data.get("patterns") or []:
                try:
                    if re.fullmatch(pat, gid):
                        e = entry
                        break
                except re.error:
                    continue
        if e:
            hits.append({"source": "mozilla_legacy", "label": st["label"], "home": st["home"], "blocked": True, **e})
        if not offline:
            b = _amo_block(gid)
            statuses.append({"label": "Mozilla add-on blocklist (live)", "home": "https://addons.mozilla.org/",
                             "fetched": time.time(), "stale": False})
            if b:
                hits.append({"source": "mozilla", "label": "Mozilla add-on blocklist", "home": "https://addons.mozilla.org/",
                             "name": next(iter((b.get("addon_name") or {}).values()), "") if isinstance(b.get("addon_name"), dict) else "",
                             "reason": (b.get("reason") or "")[:300], "added": (b.get("created") or "")[:10],
                             "blocked": bool(b.get("is_all_versions") or b.get("blocked")),
                             "soft": bool(b.get("soft_blocked")) and not b.get("blocked"),
                             "links": [u for u in [(b.get("url") or {}).get("url")] if u]})
    return {"hits": hits, "sources": statuses}


def _severity(h: dict) -> str:
    if h["source"] == "tpci":
        return "critical" if h.get("confirmed") else "high"
    if h["source"] == "sentry":
        r = (h.get("reason") or "").lower()
        if "malware" in r or "malicious" in r:
            return "critical"
        if "suspicious" in r:
            return "high"
        return "medium"           # removed for policy violations / unwanted software
    if h["source"] in ("mozilla", "mozilla_legacy"):
        return "high" if h.get("soft") else "critical"
    return "high"


def intel_findings(result: dict) -> list[Finding]:
    hits = result.get("hits") or []
    if not hits:
        return []
    order = ["critical", "high", "medium"]
    sev = min((_severity(h) for h in hits), key=order.index)
    names = sorted({h["label"] for h in hits})
    ev = []
    for h in hits[:6]:
        what = h.get("threat") or h.get("reason") or ("confirmed malicious" if h.get("confirmed") else "listed")
        extra = f" — {h['notes'][:200]}" if h.get("notes") else ""
        if h.get("hash_match"):
            extra += f" (same package hash as listed ID {h['hash_match']})"
        ev.append(Evidence(h["links"][0] if h.get("links") else h["home"], None,
                           f"{h['label']}: {what}; added {h.get('added') or '?'}{extra}"))
    transfer = any(h.get("ownership_transfer") for h in hits)
    detail = (f"This extension is on {len(names)} public known-bad list(s): {', '.join(names)}. "
              "These lists are compiled from store takedowns, vendor research and incident reports, with sources linked "
              "below. ")
    if sev == "medium":
        detail += ("The listing is for a store removal over policy or bundled software rather than confirmed malware; "
                   "still, a removed extension keeps running on machines where it is installed. ")
    if transfer:
        detail += "The list also records that the extension changed owners. "
    return [Finding("intel.known_bad", "threat_intel", sev, "On a public list of known-malicious extensions", detail, ev,
                    total_hits=len(hits),
                    opsec="Remove it from every profile, then review what it could reach (sessions, saved logins, "
                          "accounts used in that browser) and rotate sessions for sensitive accounts.")]
