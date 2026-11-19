"""Scoring calibration: well-established clean extensions vs. the ones that should stay High/Severe."""
from dossier.codescan import classify_host
from dossier.models import Finding
from dossier.ownership import ownership_findings, parse_listing_publisher
from dossier.pipeline import analyze
from dossier.scoring import compute_scores

from .conftest import MV3_BASE

CLEAN_CTX = {"stable_publisher_years": 4.2, "big_user_base": True, "users": 23_000_000,
             "open_source": True, "clean_reputation": True}


def F(rule, cat, sev, conf="high", llm=""):
    f = Finding(rule, cat, sev, rule, "d", confidence=conf)
    f.llm_verdict = llm
    return f


BROAD = [F("host.all_urls", "host_access", "high"), F("combo.scripting_all", "permissions", "high"),
         F("perm.userScripts", "permissions", "medium")]


def test_established_clean_blocker_lands_low_with_explanation():
    s = compute_scores(BROAD + [F("code.user_scripts", "remote_code", "low")], CLEAN_CTX)
    assert s["verdict"] == "Low" and s["proportionate"] and s["credit_applied"] == 12
    # ...but never below 35% of its capability score
    assert s["overall"] >= round(0.35 * s["capability"])


def test_same_access_from_an_unknown_publisher_stays_moderate():
    s = compute_scores(BROAD, {})
    assert s["verdict"] == "Moderate" and s["credits"] == []


def test_no_credits_when_anything_alarming_is_found():
    for red in (F("pub.owner_changed", "trust", "high"), F("net.analytics", "network", "medium"),
                F("data.disclosed_collection", "data_collection", "high"), F("intel.known_bad", "threat_intel", "critical")):
        assert compute_scores(BROAD + [red], CLEAN_CTX)["credits"] == []


def test_no_credits_for_heavy_behaviour_even_from_a_famous_publisher():
    heavy = BROAD + [F("ctl.native", "control", "high"), F("data.clipboard_read", "data_access", "medium"),
                     F("data.screenshot", "data_access", "medium"), F("code.exec_code_string", "remote_code", "high")]
    assert compute_scores(heavy, CLEAN_CTX)["verdict"] == "High"


def test_absence_of_tracking_alone_is_not_a_credit():
    assert compute_scores(BROAD, {"stable_publisher_years": 0})["credits"] == []


def test_ai_dismissal_now_carries_weight():
    hook = F("data.hook_network", "data_access", "high")
    before = compute_scores([hook])["behaviour"]
    hook.llm_verdict = "likely_benign"
    assert compute_scores([hook])["behaviour"] <= before * 0.2
    trust = F("web.reported_concerns", "trust", "medium", "medium", "likely_benign")
    assert compute_scores([trust])["trust_penalty"] == 0


# ------------------------------------------------------------------ false-positive fixes --

def test_single_snapshot_or_page_chrome_is_not_a_sale():
    assert "publisher" not in parse_listing_publisher("<div>Developer</div><div>Follow</div>")
    hist = {"snapshots": 1, "timeline": [{"date": "2026-11-03", "publisher": "Someone Else", "email": ""}]}
    f = ownership_findings(hist, {"publisher": "Raymond Hill"})
    assert f[0].rule == "pub.history_unclear"


def test_block_list_and_own_github_hosts_are_classified():
    assert classify_host("someonewhocares.org", "https://someonewhocares.org/hosts/hosts", set())[0] == "filter_list"
    assert classify_host("raw.githubusercontent.com", "https://raw.githubusercontent.com/darkreader/darkreader/main/cfg",
                         {"gh:darkreader"}) == ("first_party", "Publisher's own GitHub")
    assert classify_host("raw.githubusercontent.com", "https://raw.githubusercontent.com/randomuser/x/main/p",
                         {"gh:darkreader"})[0] == "code_hosting"


def test_surrogate_stub_resources_are_not_tracker_traffic(make_ext):
    stub = "(function(){ var u = 'https://pubads.g.doubleclick.net/gampad/ads'; window.googletag = {cmd: []}; })();"
    res = analyze(str(make_ext({**MV3_BASE}, {"web_accessible_resources/googletagservices_gpt.js": stub,
                                             "web_accessible_resources/chartbeat.js": "window.pSUPERFLY={};"})),
                  log=lambda *_: None)
    assert not any(e.host.endswith("doubleclick.net") for e in res.endpoints)
    assert not any(lib.name == "chartbeat" for lib in res.libraries)


def test_user_scripts_from_local_settings_are_low(make_ext):
    src = "chrome.userScripts.register([{id: 'f', js: [{code: buildFromSettings()}], matches: ['<all_urls>']}]);"
    res = analyze(str(make_ext({**MV3_BASE, "background": {"service_worker": "bg.js"}}, {"bg.js": src})),
                  log=lambda *_: None)
    assert next(f for f in res.findings if f.rule == "code.user_scripts").severity == "low"
