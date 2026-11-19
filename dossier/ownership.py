"""Publisher history from archived copies of the store listing (Internet Archive Wayback Machine).

Stores don't publish ownership history, but the Wayback Machine has years of snapshots of most popular
listings. Sampling those snapshots and reading the "Offered by" / "Developer" block shows when the
publisher changed: the moment trusted extensions are most often sold and turned into data harvesters.

Network: only web.archive.org is contacted, with a small, capped number of requests.
"""
from __future__ import annotations

import datetime as dt
import html
import json
import re
import time
import urllib.parse

from .fetch import FetchError, _get
from .models import Evidence, Finding

MAX_FETCHES = 14
TIME_BUDGET = 120.0  # seconds for the whole lookup


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _visible_lines(raw: str) -> list[str]:
    t = re.sub(r"<script.*?</script>|<style.*?</style>", "", raw, flags=re.S | re.I)
    return [ln.strip() for ln in html.unescape(re.sub(r"<[^>]+>", "\n", t)).split("\n") if ln.strip()]


def parse_listing_publisher(raw: str) -> dict:
    """Pull publisher name / email / website out of an old or new store page (Chrome or AMO)."""
    lines = _visible_lines(raw)
    out: dict = {}
    for i, ln in enumerate(lines[:400]):
        low = ln.lower()
        if low in ("offered by:", "offered by") and i + 1 < len(lines):
            out.setdefault("publisher", lines[i + 1])
        elif low.startswith("offered by") and len(ln) > 12:
            out.setdefault("publisher", ln[10:].lstrip(": ").strip())
        elif ln == "Developer" and i + 1 < len(lines) and lines[i + 1] not in ("Website", "Email"):
            out.setdefault("publisher", lines[i + 1])
        elif ln == "Email" and i + 1 < len(lines) and "@" in lines[i + 1]:
            out.setdefault("email", lines[i + 1])
    if "publisher" not in out:                       # AMO: <a class="AddonTitle-author" ...> or "by Name"
        m = re.search(r'class="[^"]*AddonTitle-author[^"]*"[^>]*>(?:\s*by\s*)?(?:<[^>]+>)*\s*([^<]+)<', raw)
        if m:
            out["publisher"] = html.unescape(m.group(1)).strip()
    m = re.search(r'href="(?:https?://web\.archive\.org/web/\d+/)?(https?://[^"]+)"[^>]*>\s*(?:<[^>]+>\s*)*Website', raw)
    if m:
        out["website"] = html.unescape(m.group(1))
    if "email" not in out:
        m = re.search(r"mailto:([^\"'?>\s]+@[^\"'?>\s]+)", raw)
        if m:
            out["email"] = html.unescape(m.group(1))
    pub = (out.get("publisher") or "").strip()
    if pub.lower() in _NOT_A_NAME or len(pub) < 2 or len(pub) > 80:
        out.pop("publisher", None)   # page chrome mistaken for a name (e.g. a "Follow" button)
    return out


_NOT_A_NAME = {"follow", "website", "email", "phone", "report", "developer", "offered by", "privacy policy",
               "support", "add to chrome", "add to firefox", "share", "more", "see all", "contact", "details"}


def listing_urls(browser: str, ext_id: str, slug: str = "") -> list[str]:
    if browser == "chrome":
        urls = [f"chromewebstore.google.com/detail/{slug}/{ext_id}"] if slug else []
        urls += [f"chrome.google.com/webstore/detail/{slug}/{ext_id}"] if slug else []
        urls += [f"chrome.google.com/webstore/detail/{ext_id}"]
        return urls
    if browser == "firefox":
        return [f"addons.mozilla.org/en-US/firefox/addon/{slug or ext_id}/"]
    return []


def _snapshots(url: str) -> list[tuple[str, str]]:
    q = urllib.parse.urlencode({"url": url, "output": "json", "fl": "timestamp,original",
                                "filter": "statuscode:200", "collapse": "timestamp:6"})
    try:
        rows = json.loads(_get(f"https://web.archive.org/cdx/search/cdx?{q}", accept="application/json").decode() or "[]")
    except (FetchError, ValueError):
        return []
    return [(r[0], r[1]) for r in rows[1:]]


def _date(ts: str) -> str:
    return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"


def publisher_history(browser: str, ext_id: str, slug: str = "", log=lambda *_: None) -> dict:
    """Returns {"timeline": [{"date", "publisher", "email", "website"}...], "changes": [...], "snapshots": n}."""
    start = time.monotonic()
    snaps: dict[str, str] = {}
    for u in listing_urls(browser, ext_id, slug):
        for ts, orig in _snapshots(u):
            snaps.setdefault(ts, orig)
    ordered = sorted(snaps.items())
    if not ordered:
        return {"timeline": [], "changes": [], "snapshots": 0}
    log(f"  checking publisher history in {len(ordered)} archived store snapshots ...")
    cache: dict[int, dict] = {}
    fetches = 0

    def info(i: int) -> dict:
        nonlocal fetches
        if i in cache:
            return cache[i]
        if fetches >= MAX_FETCHES or time.monotonic() - start > TIME_BUDGET:
            return {}
        fetches += 1
        ts, orig = ordered[i]
        try:
            raw = _get(f"https://web.archive.org/web/{ts}id_/{orig if orig.startswith('http') else 'https://' + orig}",
                       accept="text/html").decode("utf-8", "replace")
            cache[i] = {**parse_listing_publisher(raw), "date": _date(ts)}
        except FetchError:
            cache[i] = {"date": _date(ts)}
        return cache[i]

    # Evenly sample, then bisect every boundary where the publisher differs.
    n = len(ordered)
    picks = sorted({0, n - 1, *[round(k * (n - 1) / 5) for k in range(1, 5)]})
    for i in picks:
        info(i)
    # Narrow down boundaries, organisation (domain) changes first: they matter more than renames.
    while True:
        known = sorted(i for i, v in cache.items() if v.get("publisher"))
        gaps = [(a, b) for a, b in zip(known, known[1:]) if b - a > 1 and (
            _domain(cache[a]) != _domain(cache[b]) or _norm(cache[a]["publisher"]) != _norm(cache[b]["publisher"]))]
        gaps.sort(key=lambda g: _domain(cache[g[0]]) == _domain(cache[g[1]]))
        mids = [m for m in ((a + b) // 2 for a, b in gaps) if m not in cache]
        if not mids or not info(mids[0]):   # nothing left to narrow, or out of budget
            break
    timeline = [cache[i] for i in sorted(cache) if cache[i].get("publisher")]
    changes = []
    for prev, cur in zip(timeline, timeline[1:]):
        if _norm(prev["publisher"]) != _norm(cur["publisher"]):
            changes.append({"from": prev["publisher"], "to": cur["publisher"],
                            "between": f"{prev['date']} and {cur['date']}"})
    return {"timeline": timeline, "changes": changes, "snapshots": n, "fetched": fetches}


def _domain(e: dict) -> str:
    """Organisation identity from the contact e-mail or website domain (survives cosmetic renames)."""
    from .knowledge import registrable_domain
    if e.get("email") and "@" in e["email"]:
        return registrable_domain(e["email"].rsplit("@", 1)[1])
    m = re.match(r"^https?://([^/:?#]+)", e.get("website") or "")
    return registrable_domain(m.group(1)) if m else ""


def _spans(tl: list[dict], key) -> list[dict]:
    out: list[dict] = []
    for e in tl:
        if out and key(e) == key(out[-1]["entry"]):
            out[-1]["to"] = e["date"]
            out[-1]["entry"] = {**out[-1]["entry"], **{k: v for k, v in e.items() if v}}
        else:
            out.append({"entry": dict(e), "from": e["date"], "to": e["date"]})
    return out


def ownership_findings(hist: dict, current: dict) -> list[Finding]:
    """Turn the archived timeline plus today's live listing ({publisher, email, website}) into findings."""
    tl = list(hist.get("timeline") or [])
    if current.get("publisher"):
        tl.append({**current, "date": "today"})
    if len(tl) < 2:
        return []
    # Fill unknown domains from neighbours with the same name so a missing e-mail isn't read as a change.
    for i, e in enumerate(tl):
        if not _domain(e):
            same = [x for x in tl if _norm(x["publisher"]) == _norm(e["publisher"]) and _domain(x)]
            if same:
                e["email"] = same[0].get("email", "")
                e["website"] = same[0].get("website", "")
    by_org = _spans(tl, lambda e: _domain(e) or _norm(e["publisher"]))
    by_name = _spans(tl, lambda e: _norm(e["publisher"]))
    evidence = [Evidence("web.archive.org", None,
                         f"{s['from']} → {s['to']}: {s['entry']['publisher']}"
                         + (f" <{s['entry']['email']}>" if s['entry'].get('email') else "")
                         + (f" [{_domain(s['entry'])}]" if _domain(s['entry']) and not s['entry'].get('email') else ""))
                for s in by_name][:10]
    first = tl[0]["date"]
    if len(by_org) < 2:
        if len(by_name) < 2:
            return [Finding("pub.history_stable", "trust", "info", "Same publisher in archived store listings",
                            f"{hist.get('snapshots', 0)} archived snapshots of the listing since {first} show the same "
                            f"publisher, '{tl[0]['publisher']}'. No sign of a change of hands.", evidence)]
        return [Finding("pub.publisher_renamed", "trust", "low", "Publisher name changed, same organisation",
                        "The listed publisher name changed over time but the contact domain stayed the same "
                        f"({_domain(tl[-1]) or 'unknown'}), which usually means a rename rather than a sale.", evidence)]
    prev, cur = by_org[-2], by_org[-1]
    if prev["from"] == prev["to"] and len(by_org) == 2:
        # The "previous owner" rests on a single archived snapshot: too thin to call it a sale (parsing noise).
        return [Finding("pub.history_unclear", "trust", "info", "Publisher history inconclusive",
                        "Only one archived snapshot shows a different publisher, which is not enough to establish a change "
                        "of owner.", evidence)]
    pe, ce = prev["entry"], cur["entry"]
    when = f"between {prev['to']} and {cur['from']}"
    recent = cur["from"] == "today" or _is_recent(cur["from"])
    return [Finding(
        "pub.owner_changed", "trust", "high" if recent else "medium",
        "The extension has changed owners",
        f"Archived copies of the store listing show the publisher changing from '{pe['publisher']}' "
        f"({_domain(pe) or 'unknown domain'}) to '{ce['publisher']}' ({_domain(ce) or 'unknown domain'}) {when}. "
        "Extensions with an established user base are regularly bought and then updated to collect or sell browsing "
        "data. The ratings, reviews, user count and badges you see were earned by the previous owner.",
        evidence,
        opsec="Treat it as a new, unknown vendor: re-check what it collects and who now receives it, and look for "
              "statements from the previous owner (they sometimes disown the extension publicly).")]


def _is_recent(date_str: str, days: int = 730) -> bool:
    try:
        d = dt.date.fromisoformat(date_str[:10])
    except ValueError:
        return True   # "today" etc.
    return (dt.date.today() - d).days <= days
