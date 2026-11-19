import io
import json
import struct
import zipfile

import pytest

from dossier.config import llm_config
from dossier.fetch import FetchError, resolve_target
from dossier.manifest import analyze_csp, build_permissions, analyze_manifest, load_manifest
from dossier.pipeline import analyze
from dossier.report import render_html
from dossier.unpack import UnpackError, crx_to_zip_bytes, extract_package

from .conftest import MV3_BASE


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for k, v in files.items():
            z.writestr(k, v)
    return buf.getvalue()


def _rules(manifest):
    return {f.rule for f in analyze_manifest(manifest, build_permissions(manifest))}


# ------------------------------------------------------------------ unpack -----------

def test_crx3_header_is_stripped():
    z = _zip({"manifest.json": "{}"})
    header = b"\x00" * 20
    crx = b"Cr24" + struct.pack("<I", 3) + struct.pack("<I", len(header)) + header + z
    assert crx_to_zip_bytes(crx) == z


def test_crx2_header_is_stripped():
    z = _zip({"manifest.json": "{}"})
    crx = b"Cr24" + struct.pack("<III", 2, 4, 3) + b"KEYSIG" + b"X" + z
    assert crx_to_zip_bytes(crx) == z


def test_zip_slip_entries_are_skipped(tmp_path):
    data = _zip({"manifest.json": "{}", "../../evil.txt": "x", "/abs.txt": "y", "ok/a.js": "1"})
    st = extract_package(data, tmp_path / "out")
    assert (tmp_path / "out" / "ok" / "a.js").exists()
    assert not (tmp_path / "evil.txt").exists()
    assert len(st["skipped"]) == 2


def test_garbage_is_rejected():
    with pytest.raises(UnpackError):
        crx_to_zip_bytes(b"not an extension")


# ------------------------------------------------------------------ targets ----------

@pytest.mark.parametrize("raw,browser,ext_id", [
    ("https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh", "chrome", "ddkjiahejlhfcafbddmgiahcphecmpfh"),
    ("https://chrome.google.com/webstore/detail/x/ddkjiahejlhfcafbddmgiahcphecmpfh?hl=en", "chrome", "ddkjiahejlhfcafbddmgiahcphecmpfh"),
    ("https://microsoftedge.microsoft.com/addons/detail/ublock-origin/odfafepnkmbhccpbejgmiehpchacaeak", "edge", "odfafepnkmbhccpbejgmiehpchacaeak"),
    ("https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/", "firefox", "ublock-origin"),
    ("ddkjiahejlhfcafbddmgiahcphecmpfh", "chrome", "ddkjiahejlhfcafbddmgiahcphecmpfh"),
    ("uBlock0@raymondhill.net", "firefox", "uBlock0@raymondhill.net"),
])
def test_resolve_target(raw, browser, ext_id):
    t = resolve_target(raw)
    assert (t.kind, t.browser, t.ext_id) == ("store", browser, ext_id)


def test_resolve_bare_id_for_edge():
    assert resolve_target("odfafepnkmbhccpbejgmiehpchacaeak", "edge").browser == "edge"


def test_resolve_rejects_nonsense():
    with pytest.raises(FetchError):
        resolve_target("definitely not a thing")


# ------------------------------------------------------------------ manifest ---------

def test_manifest_with_comments_and_bom(tmp_path):
    (tmp_path / "manifest.json").write_bytes(
        '﻿{ // comment\n "name": "x", /* block */ "version": "1", "manifest_version": 3, }'.encode("utf-8"))
    assert load_manifest(tmp_path)["name"] == "x"


def test_all_urls_and_cookie_combo():
    m = {**MV3_BASE, "permissions": ["cookies"], "host_permissions": ["<all_urls>"]}
    r = _rules(m)
    assert {"host.all_urls", "combo.cookies_all"} <= r


def test_active_tab_only_is_quiet():
    m = {**MV3_BASE, "permissions": ["activeTab", "storage"]}
    assert not {f for f in _rules(m) if not f.startswith("perm.optional")}


def test_offstore_update_url():
    assert "update.offstore" in _rules({**MV3_BASE, "update_url": "https://updates.shady.example/u.xml"})
    assert "update.offstore" not in _rules({**MV3_BASE, "update_url": "https://clients2.google.com/service/update2/crx"})


def test_csp_remote_and_eval():
    m = {"manifest_version": 2, "content_security_policy": "script-src 'self' 'unsafe-eval' https://cdn.x.com; object-src 'self'"}
    r = {f.rule for f in analyze_csp(m)}
    assert r == {"csp.unsafe_eval", "csp.remote_script"}


def test_web_accessible_fingerprint():
    m = {**MV3_BASE, "web_accessible_resources": [{"resources": ["a.png"], "matches": ["<all_urls>"]}]}
    assert "fp.war" in _rules(m)
    m["web_accessible_resources"][0]["use_dynamic_url"] = True
    assert "fp.war" not in _rules(m)


def test_search_hijack():
    m = {**MV3_BASE, "chrome_settings_overrides": {"search_provider": {"search_url": "https://srch.example/?q={searchTerms}"}}}
    assert "override.search" in _rules(m)


# ------------------------------------------------------------------ report -----------

def test_report_escapes_hostile_extension_content(make_ext):
    evil = '<script>alert(1)</script><img src=x onerror=alert(2)>'
    root = make_ext({**MV3_BASE, "name": evil, "description": evil, "background": {"service_worker": "bg.js"}},
                    {"bg.js": f"fetch('https://a.evil-host.com/{evil}')"})
    html = render_html(analyze(str(root), log=lambda *_: None))
    assert "<script>alert(1)" not in html
    assert "onerror=alert" not in html.replace("onerror=alert(2)&gt;", "")  # only escaped forms remain
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    # self-contained: no external fetches from the report itself
    assert 'src="http' not in html and "href=\"http" not in html.split("Store listing")[0]


def test_report_renders_from_crx_file(tmp_path):
    z = _zip({"manifest.json": json.dumps({**MV3_BASE, "permissions": ["tabs"]})})
    crx = b"Cr24" + struct.pack("<II", 3, 0) + z
    p = tmp_path / "x.crx"
    p.write_bytes(crx)
    res = analyze(str(p), log=lambda *_: None)
    assert res.info.sha256 and res.info.name == "Test Ext"
    assert "Test Ext" in render_html(res)


# ------------------------------------------------------------------ config -----------

def test_llm_config_local_needs_no_key(monkeypatch):
    for k in ("OPENAI_API_KEY", "DOSSIER_LLM_API_KEY", "DOSSIER_LLM_MODEL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DOSSIER_LLM_BASE_URL", "http://localhost:11434/v1")
    c = llm_config(model="llama3.1")
    assert c.enabled and c.is_local and c.provider_label.startswith("Ollama")


def test_llm_disabled_without_key(monkeypatch):
    for k in ("OPENAI_API_KEY", "DOSSIER_LLM_API_KEY", "DOSSIER_LLM_BASE_URL"):
        monkeypatch.delenv(k, raising=False)
    assert not llm_config().enabled
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    assert not llm_config(no_llm=True).enabled
