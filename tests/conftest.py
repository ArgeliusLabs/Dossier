import json
import os
from pathlib import Path

import pytest


def pytest_addoption(parser):
    parser.addoption("--network", action="store_true", help="run tests that download real extensions from the stores")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--network") or os.environ.get("DOSSIER_NETWORK_TESTS") == "1":
        return
    skip = pytest.mark.skip(reason="needs --network")
    for item in items:
        if "network" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def make_ext(tmp_path):
    """Build an unpacked extension: make_ext(manifest_dict, {"path.js": "source", ...})."""
    def _make(manifest: dict, files: dict[str, str] | None = None) -> Path:
        root = tmp_path / "ext"
        root.mkdir(exist_ok=True)
        (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        for rel, src in (files or {}).items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(src, encoding="utf-8")
        return root
    return _make


MV3_BASE = {"manifest_version": 3, "name": "Test Ext", "version": "1.0"}


@pytest.fixture(autouse=True)
def _isolate_network_lookups(request, monkeypatch, tmp_path):
    """Offline tests never download threat-intel lists; every test gets its own cache folder."""
    monkeypatch.setenv("DOSSIER_CACHE_DIR", str(tmp_path / "cache"))
    if "network" not in request.keywords:
        monkeypatch.setattr("dossier.pipeline.check_intel", lambda *a, **k: {})
