"""Resolve user input (store URL, ID, file, folder) and fetch packages + store metadata.

Only stdlib networking is used. Store metadata is best-effort: a failure there never
stops the analysis, it just leaves the "who's behind it" section thinner.
"""
from __future__ import annotations

import datetime as dt
import gzip
import html
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
CHROME_PRODVERSION = "150.0"  # too low and the store refuses extensions with a newer minimum_chrome_version
TIMEOUT = 60
MAX_DOWNLOAD = 250 * 1024 * 1024

CHROME_ID = re.compile(r"^[a-p]{32}$")


class FetchError(Exception):
    def __init__(self, msg: str, status: int | None = None):
        super().__init__(msg)
        self.status = status


@dataclass
class Target:
    kind: str                 # "store" | "file" | "dir"
    browser: str = "unknown"  # chrome | edge | firefox | unknown
    ext_id: str = ""          # chrome/edge id, or AMO slug/guid
    path: Path | None = None
    store_url: str = ""
    raw: str = ""
    extra: dict = field(default_factory=dict)


def resolve_target(raw: str, browser_hint: str | None = None) -> Target:
    s = raw.strip().strip('"')
    p = Path(s)
    if p.exists():
        if p.is_dir():
            return Target("dir", browser_hint or "unknown", path=p, raw=raw)
        suffix = p.suffix.lower()
        browser = browser_hint or {".xpi": "firefox", ".crx": "chrome"}.get(suffix, "unknown")
        return Target("file", browser, path=p, raw=raw)

    if re.match(r"^https?://", s, re.I):
        u = urllib.parse.urlparse(s)
        host = u.netloc.lower()
        parts = [x for x in u.path.split("/") if x]
        if host in ("chromewebstore.google.com", "chrome.google.com"):
            ids = [x for x in parts if CHROME_ID.match(x)]
            if not ids:
                raise FetchError(f"Could not find a 32-character extension ID in {s}")
            return Target("store", "chrome", ids[-1], store_url=chrome_store_url(ids[-1]), raw=raw)
        if host == "microsoftedge.microsoft.com":
            ids = [x for x in parts if CHROME_ID.match(x)]
            if not ids:
                raise FetchError(f"Could not find an Edge extension ID in {s}")
            return Target("store", "edge", ids[-1], store_url=edge_store_url(ids[-1]), raw=raw)
        if host.endswith("addons.mozilla.org"):
            if "addon" not in parts or parts.index("addon") + 1 >= len(parts):
                raise FetchError(f"Could not find an add-on slug in {s}")
            slug = urllib.parse.unquote(parts[parts.index("addon") + 1])
            return Target("store", "firefox", slug, store_url=f"https://addons.mozilla.org/firefox/addon/{slug}/", raw=raw)
        raise FetchError(f"Unrecognised store URL: {s}")

    if CHROME_ID.match(s):
        browser = browser_hint if browser_hint in ("chrome", "edge") else "chrome"
        url = edge_store_url(s) if browser == "edge" else chrome_store_url(s)
        return Target("store", browser, s, store_url=url, raw=raw)

    # Firefox slug / GUID / email-style id
    looks_like_slug = browser_hint is None and re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,80}", s, re.I)
    if browser_hint == "firefox" or "@" in s or s.startswith("{") or looks_like_slug:
        return Target("store", "firefox", s, store_url=f"https://addons.mozilla.org/firefox/addon/{urllib.parse.quote(s)}/", raw=raw)

    raise FetchError(
        f"'{raw}' is not an existing file/folder, store URL, or 32-character Chrome/Edge ID. "
        "For a Firefox add-on slug use --browser firefox."
    )


def chrome_store_url(ext_id: str) -> str:
    return f"https://chromewebstore.google.com/detail/{ext_id}"


def edge_store_url(ext_id: str) -> str:
    return f"https://microsoftedge.microsoft.com/addons/detail/{ext_id}"


def _ssl_context() -> ssl.SSLContext:
    """Prefer certifi's CA bundle when present: standalone binaries can't always see the OS trust store."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


_SSL = _ssl_context()


def _get(url: str, accept: str = "*/*", limit: int = MAX_DOWNLOAD) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept, "Accept-Language": "en-US,en;q=0.8"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_SSL) as r:
            data = r.read(limit + 1)
    except urllib.error.HTTPError as e:
        raise FetchError(f"HTTP {e.code} fetching {url.split('?')[0]}", e.code) from e
    except urllib.error.URLError as e:
        raise FetchError(f"Network error fetching {url.split('?')[0]}: {e.reason}") from e
    if len(data) > limit:
        raise FetchError("Download exceeds size limit.")
    if data[:2] == b"\x1f\x8b":   # gzip body served as-is (e.g. raw Wayback Machine captures)
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError):
            pass
    return data


def _get_json(url: str):
    return json.loads(_get(url, accept="application/json").decode("utf-8", "replace"))


# ------------------------------------------------------------------ package download --

def download_package(t: Target) -> bytes:
    if t.browser == "chrome":
        url = ("https://clients2.google.com/service/update2/crx?response=redirect"
               f"&prodversion={CHROME_PRODVERSION}&acceptformat=crx2,crx3&x=id%3D{t.ext_id}%26uc")
        data = _get(url)
    elif t.browser == "edge":
        url = ("https://edge.microsoft.com/extensionwebstorebase/v1/crx?response=redirect"
               f"&x=id%3D{t.ext_id}%26installsource%3Dondemand%26uc")
        data = _get(url)
    elif t.browser == "firefox":
        meta = t.extra.get("amo") or _amo_lookup(t.ext_id)
        t.extra["amo"] = meta
        try:
            url = meta["current_version"]["file"]["url"]
        except (KeyError, TypeError) as e:
            raise FetchError("AMO did not return a download URL (add-on disabled or not listed?).") from e
        data = _get(url)
    else:
        raise FetchError("Unknown browser for download.")
    if not data or data[:4] not in (b"Cr24",) and data[:2] != b"PK":
        raise FetchError(
            f"The {t.browser} store did not return an extension package for '{t.ext_id}'. "
            "It may have been removed, be region-locked, or the ID may be wrong."
        )
    return data


# ------------------------------------------------------------------ store metadata ----

def fetch_store_metadata(t: Target) -> dict:
    """Return normalised store metadata; never raises."""
    try:
        if t.browser == "chrome":
            return _chrome_meta(t.ext_id)
        if t.browser == "edge":
            return _edge_meta(t.ext_id)
        if t.browser == "firefox":
            meta = t.extra.get("amo") or _amo_lookup(t.ext_id)
            t.extra["amo"] = meta
            return _amo_normalise(meta)
    except FetchError as e:
        if e.status == 404:
            return _not_listed(t)
        return {"error": f"Store metadata unavailable: {e}"}
    except Exception as e:  # noqa: BLE001 - metadata is optional
        return {"error": f"Store metadata unavailable: {e}"}
    return {}


def _not_listed(t: Target) -> dict:
    store = {"chrome": "Chrome Web Store", "edge": "Microsoft Edge Add-ons", "firefox": "Firefox Add-ons (AMO)"}[t.browser]
    return {"store": store, "removed": True}


def _amo_lookup(slug: str) -> dict:
    return _get_json(f"https://addons.mozilla.org/api/v5/addons/addon/{urllib.parse.quote(slug, safe='@{}')}/")


def _first_locale(v):
    if isinstance(v, dict):
        return v.get("en-US") or next((x for x in v.values() if x), "")
    return v or ""


def _amo_normalise(a: dict) -> dict:
    cv = a.get("current_version") or {}
    f = cv.get("file") or {}
    ratings = a.get("ratings") or {}
    promoted = a.get("promoted") or []
    if isinstance(promoted, dict):
        promoted = [promoted]
    home = a.get("homepage") or {}
    return {
        "store": "Firefox Add-ons (AMO)",
        "name": _first_locale(a.get("name")),
        "summary": _first_locale(a.get("summary")),
        "users": a.get("average_daily_users"),
        "users_label": "average daily users",
        "rating": ratings.get("average"),
        "rating_count": ratings.get("count"),
        "publisher": ", ".join(x.get("name", "") for x in a.get("authors", [])),
        "publisher_url": _first_locale(home.get("url") if isinstance(home, dict) else home),
        "created": a.get("created"),
        "last_updated": a.get("last_updated"),
        "version": cv.get("version"),
        "badges": [p.get("category") for p in promoted if p.get("category")],
        "license": (cv.get("license") or {}).get("slug") or (cv.get("license") or {}).get("name"),
        "has_privacy_policy": a.get("has_privacy_policy"),
        "is_disabled": a.get("is_disabled"),
        "is_experimental": a.get("is_experimental"),
        "requires_payment": a.get("requires_payment"),
        "guid": a.get("guid"),
        "slug": a.get("slug"),
        "file_hash": f.get("hash"),
        "data_collection_permissions": f.get("data_collection_permissions"),
        "support_email": _first_locale(a.get("support_email")),
        "categories": a.get("categories"),
    }


def _edge_meta(ext_id: str) -> dict:
    e = _get_json(f"https://microsoftedge.microsoft.com/addons/getproductdetailsbycrxid/{ext_id}")
    upd = e.get("lastUpdateDate")
    last = dt.datetime.fromtimestamp(upd, dt.timezone.utc).isoformat() if isinstance(upd, (int, float)) else upd
    pd = e.get("privacyData") or {}
    return {
        "store": "Microsoft Edge Add-ons",
        "name": e.get("name"),
        "summary": e.get("shortDescription"),
        "users": e.get("activeInstallCount"),
        "users_label": "active installs",
        "rating": e.get("averageRating"),
        "rating_count": e.get("ratingCount"),
        "publisher": e.get("developer"),
        "publisher_url": e.get("publisherWebsiteUri"),
        "last_updated": last,
        "version": e.get("version"),
        "badges": ["featured"] if e.get("isBadgedAsFeatured") else [],
        "privacy_url": e.get("privacyUrl"),
        "privacy_disclosures": pd.get("disclosureList"),
        "data_usage": pd.get("dataUsageList"),
        "category": e.get("category"),
    }


_CHROME_LABELS = ["Version", "Updated", "Offered by", "Size", "Developer", "Email", "Website", "Phone"]


def _chrome_meta(ext_id: str) -> dict:
    raw = _get(chrome_store_url(ext_id), accept="text/html").decode("utf-8", "replace")
    out: dict = {"store": "Chrome Web Store", "users_label": "users"}
    m = re.search(r'<meta property="og:title" content="([^"]*)"', raw)
    if m and html.unescape(m.group(1)).strip() != "Chrome Web Store":   # bare title = no such listing
        out["name"] = html.unescape(m.group(1)).replace(" - Chrome Web Store", "")
    m = re.search(r'<meta property="og:description" content="([^"]*)"', raw)
    if m:
        out["summary"] = html.unescape(m.group(1))
    m = re.search(r'<meta property="og:url" content="https://chromewebstore\.google\.com/detail/([^/"]+)/' + ext_id, raw)
    if m:
        out["slug"] = m.group(1)   # needed to find archived copies of the listing
    text = re.sub(r"<script.*?</script>|<style.*?</style>", "", raw, flags=re.S)
    lines = [ln.strip() for ln in html.unescape(re.sub(r"<[^>]+>", "\n", text)).split("\n") if ln.strip()]
    # Only trust the main listing (stop before "related" carousels).
    stop = next((i for i, ln in enumerate(lines) if ln.startswith("Related") or ln.startswith("You might also like")), len(lines))
    main = lines[:stop]
    for i, ln in enumerate(main):
        if (m := re.fullmatch(r"([\d,]+)\+? users?", ln)) and "users" not in out:
            out["users"] = int(m.group(1).replace(",", ""))
        elif ln == "Featured" and i < 40:
            out.setdefault("badges", []).append("featured")
        elif ln == "Established publisher":
            out.setdefault("badges", []).append("established publisher")
        elif (m := re.fullmatch(r"([\d.]+) out of 5", ln)) and "rating" not in out:
            out["rating"] = float(m.group(1))
        elif (m := re.fullmatch(r"([\d.]+)(K|M)? ratings?", ln)) and "rating_count" not in out:
            mult = {"K": 1_000, "M": 1_000_000}.get(m.group(2) or "", 1)
            out["rating_count"] = int(float(m.group(1)) * mult)
        elif ln in ("Trader", "Non-trader"):
            out["trader_status"] = ln
        elif ln == "Developer" and i + 1 < len(main) and "publisher" not in out:
            # Developer block: name, then postal address lines (traders), then Website/Email/Phone labels.
            out["publisher"] = main[i + 1]
            addr = []
            for nxt in main[i + 2:i + 8]:
                if nxt in _CHROME_LABELS or nxt in ("Trader", "Non-trader"):
                    break
                addr.append(nxt)
            if addr:
                out["publisher_address"] = ", ".join(addr)
        elif ln == "D-U-N-S" and "duns" not in out:
            num = next((x for x in main[i + 1:i + 5] if re.fullmatch(r"\d{9}", x)), None)
            if num:
                out["duns"] = num
        elif ln in _CHROME_LABELS and i + 1 < len(main):
            key = {"Offered by": "publisher", "Updated": "last_updated", "Version": "version",
                   "Size": "size", "Email": "support_email", "Phone": "phone"}.get(ln)
            val = main[i + 1]
            if key and key not in out and val not in _CHROME_LABELS:
                out[key] = val
    m = re.search(r'href="(https?://[^"]+)"[^>]*>\s*(?:<[^>]+>\s*)*Website', raw)
    if m and "publisher_url" not in out:
        out["publisher_url"] = html.unescape(m.group(1))
    m = re.search(r'href="(https?://[^"]+)"[^>]*>\s*(?:<[^>]+>\s*)*Privacy policy', raw, re.I)
    if m:
        out["privacy_url"] = html.unescape(m.group(1))
    if "users" not in out and "name" not in out:
        if '<meta property="og:title" content="Chrome Web Store"' in raw:
            return {"store": "Chrome Web Store", "removed": True}
        out["error"] = "Chrome Web Store page could not be parsed (layout changed?)."
    return out
