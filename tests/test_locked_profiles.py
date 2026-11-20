"""Installed extensions in locked browser profiles (antivirus / profile protection / sandboxes)."""
import io
import json
import pathlib
import zipfile

import pytest

from dossier import pipeline
from dossier.fetch import FetchError
from dossier.pipeline import analyze

from .conftest import MV3_BASE

REAL_READ = pathlib.Path.read_bytes


def _lock(monkeypatch, predicate):
    def guarded(self):
        if predicate(self):
            raise PermissionError(13, "Permission denied", str(self))
        return REAL_READ(self)
    monkeypatch.setattr(pathlib.Path, "read_bytes", guarded)


def test_some_locked_files_are_skipped_not_fatal(make_ext, monkeypatch):
    root = make_ext({**MV3_BASE, "background": {"service_worker": "bg.js"}},
                    {"bg.js": "fetch('https://api.real-endpoint.io/x')", "_locales/ar/messages.json": "{}"})
    _lock(monkeypatch, lambda p: p.name == "messages.json" and "ext" in p.parts)
    res = analyze(str(root), log=lambda *_: None)
    assert res.info.name == "Test Ext"
    assert "1 skipped" in res.info.context["Unreadable files"]
    assert any(e.host == "api.real-endpoint.io" for e in res.endpoints)


def _crx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("manifest.json", json.dumps({**MV3_BASE, "name": "Store Copy"}))
    return buf.getvalue()


def test_fully_locked_install_falls_back_to_store_copy(make_ext, monkeypatch):
    root = make_ext({**MV3_BASE}, {"a.js": "1"})
    _lock(monkeypatch, lambda p: "ext" in p.parts)
    monkeypatch.setattr(pipeline, "download_package", lambda t: _crx())
    monkeypatch.setattr(pipeline, "fetch_store_metadata", lambda t: {"store": "Chrome Web Store"})
    msgs = []
    res = analyze(str(root), store_lookup=("chrome", "a" * 32), log=msgs.append, archive=False, web=False)
    assert res.info.name == "Store Copy"
    assert "store version" in res.info.context["Analysed copy"]
    assert any("analysing the chrome store copy" in m for m in msgs)


def test_locked_and_not_on_store_gives_a_clear_error(make_ext, monkeypatch):
    root = make_ext({**MV3_BASE}, {"a.js": "1"})
    _lock(monkeypatch, lambda p: "ext" in p.parts)

    def gone(t):
        raise FetchError("HTTP 404")
    monkeypatch.setattr(pipeline, "download_package", gone)
    monkeypatch.setattr(pipeline, "fetch_store_metadata", lambda t: {})
    with pytest.raises(FetchError, match="can't be read .* no downloadable copy"):
        analyze(str(root), store_lookup=("edge", "b" * 32), log=lambda *_: None, archive=False, web=False)


def test_locked_local_folder_without_store_id_still_errors(make_ext, monkeypatch):
    root = make_ext({**MV3_BASE}, {"a.js": "1"})
    _lock(monkeypatch, lambda p: "ext" in p.parts)
    with pytest.raises(OSError):
        analyze(str(root), log=lambda *_: None)
