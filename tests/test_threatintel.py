"""Known-malicious list checks: parsing, caching, offline behaviour, severity and report output."""
import json
import time

import pytest

from dossier import threatintel as T
from dossier.fetch import FetchError
from dossier.llm import apply_triage
from dossier.pipeline import analyze
from dossier.report import render_html

from .conftest import MV3_BASE

BAD = "a" * 32
POLICY = "b" * 32
HASH = "c" * 64

TPCI_CSV = (
    '"EXTID","EXTID-NAME","DATE-DIS","DATE-ADD","SOURCE","ARTICLE","CONFIRM-MAL","THREAT-TYPE","OWNERSHIP-TRANSFER","NOTES"\n'
    f'"{BAD}","Evil VPN","2025-01-01","2025-01-02","https://research.example/evil","https://news.example/evil","1",'
    '"data-theft,spyware","1","Harvests AI chats"\n'
    '"not-an-id","x","","","","","1","","",""\n').encode()
SENTRY_CSV = (
    "﻿extension_id,name,reason,source,insert_date_fmt,blocklist,store,version,sha256\n"
    f"{POLICY},Spammy Tab,Policy Violation,Store Monitoring,2026-11-18,false,Google Chrome,1.0,{HASH}\n"
    f"{BAD},Evil VPN,Malware,https://blog.example/evil,2026-01-01,false,Google Chrome,5.0,{'d' * 64}\n").encode()
MOZ_JSON = json.dumps({"data": [
    {"guid": "evil@addon", "details": {"name": "Evil", "why": "Malware", "bug": "https://bugzilla.example/1"},
     "last_modified": 1600000000000},
    {"guid": "/^bad\\d+@x\\.com$/", "details": {"name": "Pattern", "why": "Spyware family"}, "last_modified": 0}]}).encode()


@pytest.fixture
def fake_net(monkeypatch):
    calls = []

    def fake_get(url, accept="*/*", limit=0):
        calls.append(url)
        if "chrome-mal-ids" in url:
            return TPCI_CSV
        if "malicious_extension_sentry" in url:
            return SENTRY_CSV
        if "firefox.settings" in url:
            return MOZ_JSON
        if "blocklist/block/" in url:
            raise FetchError("not blocked", 404)
        raise AssertionError(url)

    monkeypatch.setattr(T, "_get", fake_get)
    return calls


def test_confirmed_malicious_id_is_critical_with_sources(fake_net):
    r = T.check("chrome", BAD)
    assert {h["source"] for h in r["hits"]} == {"tpci", "sentry"}
    f = T.intel_findings(r)[0]
    assert f.severity == "critical" and f.rule == "intel.known_bad"
    assert "research.example" in f.evidence[0].file and "changed owners" in f.detail


def test_policy_removal_is_medium(fake_net):
    f = T.intel_findings(T.check("edge", POLICY))[0]
    assert f.severity == "medium" and "policy" in f.detail


def test_package_hash_match_catches_renamed_clone(fake_net):
    r = T.check("chrome", "e" * 32, sha256=HASH)
    assert r["hits"] and r["hits"][0]["hash_match"] == POLICY


def test_clean_id_has_no_findings_but_lists_were_checked(fake_net):
    r = T.check("chrome", "f" * 32)
    assert r["hits"] == [] and len(r["sources"]) == 2 and T.intel_findings(r) == []


def test_firefox_exact_and_pattern(fake_net):
    assert T.check("firefox", "x", guid="evil@addon")["hits"][0]["blocked"]
    assert T.check("firefox", "x", guid="bad42@x.com")["hits"][0]["reason"] == "Spyware family"
    assert T.check("firefox", "x", guid="good@x.com")["hits"] == []


def test_cache_is_reused_and_works_offline(fake_net, monkeypatch):
    T.check("chrome", BAD)
    n = len(fake_net)
    T.check("chrome", BAD)
    assert len(fake_net) == n                     # fresh cache: no new downloads

    def down(*a, **k):
        raise FetchError("offline")
    monkeypatch.setattr(T, "_get", down)
    for p in T.cache_dir().glob("intel-*.json"):  # make the cache stale
        d = json.loads(p.read_text(encoding="utf-8"))
        if "fetched" in d:
            d["fetched"] = time.time() - 3 * 86400
            p.write_text(json.dumps(d), encoding="utf-8")
    r = T.check("chrome", BAD)
    assert r["hits"] and all(s["stale"] for s in r["sources"]) and "update failed" in r["sources"][0]["error"]


def test_no_cache_and_offline_degrades_gracefully(monkeypatch):
    def down(*a, **k):
        raise FetchError("offline")
    monkeypatch.setattr(T, "_get", down)
    r = T.check("chrome", BAD)
    assert r["hits"] == [] and all("unavailable" in s["error"] for s in r["sources"])


def test_hit_shows_banner_and_cannot_be_dismissed_by_ai(fake_net, make_ext, monkeypatch):
    monkeypatch.setattr("dossier.pipeline.check_intel", T.check)
    root = make_ext({**MV3_BASE}, {"a.js": "1"})
    res = analyze(str(root), store_lookup=None, log=lambda *_: None)
    res.info.ext_id = BAD
    res.intel = T.check("chrome", BAD)
    res.findings += T.intel_findings(res.intel)
    res.findings[-1].id = "F99"
    res.llm = {"finding_triage": [{"id": "F99", "verdict": "likely_benign", "reason": "looks fine"}]}
    apply_triage(res)
    assert res.findings[-1].llm_verdict == ""
    html = render_html(res)
    assert "On a public list of known-malicious extensions" in html and "research.example" in html


def test_mozilla_block_only_counts_for_blocked_versions(monkeypatch):
    block = {"guid": "foxyproxy@eric.h.jung", "blocked": [], "soft_blocked": ["6.6"], "reason": "Version deleted",
             "is_all_versions": False, "addon_name": {"en-US": "FoxyProxy"}}
    monkeypatch.setattr(T, "_amo_block", lambda g: block)
    monkeypatch.setattr(T, "load_source", lambda *a, **k: ({}, {"label": "x", "home": "h"}))
    assert T.check("firefox", "x", guid="foxyproxy@eric.h.jung", version="9.9")["hits"] == []
    # housekeeping reason: ignored even for the listed version
    assert T.check("firefox", "x", guid="foxyproxy@eric.h.jung", version="6.6")["hits"] == []
    block.update(reason="Malware: steals credentials", soft_blocked=[], blocked=["1.0"])
    assert T.check("firefox", "x", guid="foxyproxy@eric.h.jung", version="1.0")["hits"]
    assert not T.check("firefox", "x", guid="foxyproxy@eric.h.jung", version="2.0")["hits"]


def test_legacy_blocklist_version_ranges():
    assert T._in_ranges("1.5", [["1.0", "2.0"]]) and not T._in_ranges("2.1", [["1.0", "2.0"]])
    assert T._in_ranges("9", [["0", "*"]]) and T._in_ranges("", [["1", "2"]])
