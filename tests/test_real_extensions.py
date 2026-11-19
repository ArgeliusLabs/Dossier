"""Integration tests against real store extensions. Run with:  pytest --network

These pin down the behaviour we care about on known extensions, not exact scores
(store packages change). No LLM is used here.
"""
import pytest

from dossier.pipeline import analyze

pytestmark = pytest.mark.network


def _rules(res):
    return {f.rule for f in res.findings}


def test_ublock_origin_lite_is_not_drowned_in_filter_list_noise():
    res = analyze("ddkjiahejlhfcafbddmgiahcphecmpfh", log=lambda *_: None)
    assert "host.all_urls" in _rules(res)
    # Filter lists mention thousands of ad/tracker hosts; none of them should become "trackers".
    assert not _rules(res) & {"net.advertising", "net.analytics", "net.affiliate", "code.obfuscated", "code.fetch_eval"}
    assert res.verdict in ("Low", "Moderate")
    assert res.info.store.get("users", 0) > 1_000_000


def test_urban_vpn_page_hooking_and_extension_control():
    res = analyze("eppiocemhmnlbhjplcgkofciiegomcon", log=lambda *_: None)
    assert {"data.hook_network", "ctl.manage_ext", "ctl.proxy"} <= _rules(res)
    assert res.verdict in ("High", "Severe")


def test_firefox_ublock_origin_from_amo():
    res = analyze("https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/", log=lambda *_: None)
    assert res.info.browser == "firefox" and res.info.manifest_version == 2
    assert "mv.v2" in _rules(res)
    assert res.info.store.get("badges")


def test_edge_store_download():
    res = analyze("odfafepnkmbhccpbejgmiehpchacaeak", browser="edge", log=lambda *_: None)
    assert res.info.name and res.info.store.get("store") == "Microsoft Edge Add-ons"


def test_instant_data_scraper_sale_is_caught():
    """Sold by Web Robots to Flavr Technology, LP in early 2026; the store listing gives no hint of it."""
    res = analyze("ofaokhiedipichpaobibbnahnkdoiiah", log=lambda *_: None)
    assert {"pub.owner_changed", "data.disclosed_collection", "data.consent_flow", "net.analytics"} <= _rules(res)
    timeline = " ".join(e["publisher"] for e in res.ownership["timeline"])
    assert "webrobots" in timeline.lower()
    assert res.verdict in ("High", "Severe")
