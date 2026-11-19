"""Discover extensions installed in local browser profiles (read-only).

Supports Chromium-family browsers (Chrome, Edge, Brave, Chromium, Vivaldi, Opera) and Firefox,
on Windows, macOS and Linux. Nothing in the profiles is modified.
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

CHROME_ID = re.compile(r"^[a-p]{32}$")


@dataclass
class InstalledExtension:
    browser: str        # chrome | edge | brave | chromium | vivaldi | opera | firefox
    store: str          # which store to query: chrome | edge | firefox | ""
    profile: str        # human profile name
    ext_id: str
    path: Path          # unpacked folder (Chromium) or .xpi file (Firefox)
    version: str = ""
    enabled: bool | None = None
    name: str = ""


def _chromium_roots() -> dict[str, Path]:
    home = Path.home()
    if sys.platform == "win32":
        la = Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local"))
        ra = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        return {"chrome": la / "Google/Chrome/User Data", "edge": la / "Microsoft/Edge/User Data",
                "brave": la / "BraveSoftware/Brave-Browser/User Data", "chromium": la / "Chromium/User Data",
                "vivaldi": la / "Vivaldi/User Data", "opera": ra / "Opera Software/Opera Stable"}
    if sys.platform == "darwin":
        a = home / "Library/Application Support"
        return {"chrome": a / "Google/Chrome", "edge": a / "Microsoft Edge", "brave": a / "BraveSoftware/Brave-Browser",
                "chromium": a / "Chromium", "vivaldi": a / "Vivaldi", "opera": a / "com.operasoftware.Opera"}
    c = home / ".config"
    return {"chrome": c / "google-chrome", "edge": c / "microsoft-edge", "brave": c / "BraveSoftware/Brave-Browser",
            "chromium": c / "chromium", "vivaldi": c / "vivaldi", "opera": c / "opera"}


def _firefox_root() -> Path:
    home = Path.home()
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", home / "AppData/Roaming")) / "Mozilla/Firefox/Profiles"
    if sys.platform == "darwin":
        return home / "Library/Application Support/Firefox/Profiles"
    return home / ".mozilla/firefox"


def _read_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {}


def _version_key(v: str):
    return [int(x) if x.isdigit() else 0 for x in re.split(r"[._-]", v.split("_")[0])]


def _dir_name(root: Path) -> str:
    from .manifest import load_manifest, resolve_i18n
    try:
        m = load_manifest(root)
        return resolve_i18n(root, m, m.get("name", ""))
    except (OSError, ValueError):
        return ""


def _xpi_name(xpi: Path) -> str:
    import zipfile
    try:
        with zipfile.ZipFile(xpi) as z:
            m = json.loads(z.read("manifest.json").decode("utf-8-sig", "replace"))
            name = m.get("name", "")
            k = re.fullmatch(r"__MSG_(\w+)__", name or "")
            if k:
                loc = m.get("default_locale", "en")
                msgs = json.loads(z.read(f"_locales/{loc}/messages.json").decode("utf-8-sig", "replace"))
                name = next((v.get("message", name) for kk, v in msgs.items() if kk.lower() == k.group(1).lower()), name)
            return name
    except (OSError, KeyError, ValueError, zipfile.BadZipFile):
        return ""


def discover_chromium(browser: str, root: Path) -> list[InstalledExtension]:
    if not root.is_dir():
        return []
    names = (_read_json(root / "Local State").get("profile") or {}).get("info_cache") or {}
    profiles = [root] if browser == "opera" else [
        d for d in root.iterdir() if d.is_dir() and (d.name == "Default" or d.name.startswith("Profile "))]
    out = []
    for prof in profiles:
        ext_dir = prof / "Extensions"
        if not ext_dir.is_dir():
            continue
        prefs = _read_json(prof / "Secure Preferences").get("extensions", {}).get("settings", {}) or \
            _read_json(prof / "Preferences").get("extensions", {}).get("settings", {})
        label = (names.get(prof.name) or {}).get("name") or prof.name
        for d in sorted(ext_dir.iterdir()):
            if not (d.is_dir() and CHROME_ID.match(d.name)):
                continue
            versions = sorted((v for v in d.iterdir() if (v / "manifest.json").is_file()), key=lambda v: _version_key(v.name))
            if not versions:
                continue
            st = prefs.get(d.name) or {}
            enabled = None
            if "state" in st:
                enabled = st.get("state") == 1
            elif "disable_reasons" in st:
                enabled = not st.get("disable_reasons")
            elif st:
                enabled = True   # known to the profile with no disable reason
            store = "edge" if browser == "edge" else "chrome"
            out.append(InstalledExtension(browser, store, label, d.name, versions[-1],
                                          versions[-1].name.split("_")[0], enabled, _dir_name(versions[-1])))
    return out


def discover_firefox(root: Path) -> list[InstalledExtension]:
    if not root.is_dir():
        return []
    out = []
    for prof in sorted(p for p in root.iterdir() if p.is_dir()):
        meta = {a.get("id"): a for a in _read_json(prof / "extensions.json").get("addons", []) if isinstance(a, dict)}
        ext_dir = prof / "extensions"
        if not ext_dir.is_dir():
            continue
        for x in sorted(ext_dir.glob("*.xpi")):
            ext_id = x.stem
            m = meta.get(ext_id, {})
            if m.get("type") not in (None, "extension"):
                continue  # themes, dictionaries, language packs
            enabled = (m.get("active") if "active" in m else None)
            dm = m.get("defaultLocale") or {}
            out.append(InstalledExtension("firefox", "firefox", prof.name.split(".", 1)[-1], ext_id, x,
                                          str(m.get("version", "")), enabled, dm.get("name") or _xpi_name(x)))
    return out


def discover_all(browsers: set[str] | None = None) -> list[InstalledExtension]:
    found: list[InstalledExtension] = []
    for b, root in _chromium_roots().items():
        if not browsers or b in browsers:
            found += discover_chromium(b, root)
    if not browsers or "firefox" in browsers:
        found += discover_firefox(_firefox_root())
    return found
