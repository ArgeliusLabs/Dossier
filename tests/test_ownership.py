"""Ownership history, data-collection disclosures, web reputation and the lexer fixes behind them."""
from dossier.codescan import lex
from dossier.ownership import ownership_findings, parse_listing_publisher
from dossier.pipeline import analyze
from dossier.reputation import _sanitise, reputation_findings

from .conftest import MV3_BASE

OLD_STORE = ('<html><body><div class="e-f-Me"><span class="p0XxU-ua">Offered by:</span> '
             '<a href="http://webrobots.io" rel="nofollow">webrobots.io</a></div>'
             '<a href="mailto:info@webrobots.io">mail</a></body></html>')
OLDER_STORE = '<div title="x">offered by <a href="http://webrobots.io">webrobots.io</a></div>'
NEW_STORE = ('<div>Developer</div><div>Flavr Technology, LP</div><div>251 Little Falls Dr</div>'
             '<a href="https://flavrtech.co">Website</a><div>Email</div><div>support@flavrtech.co</div>')


def rules(res):
    return {f.rule for f in res.findings}


# ------------------------------------------------------------------ listing parsing ----

def test_parse_old_and_new_store_layouts():
    assert parse_listing_publisher(OLD_STORE) == {"publisher": "webrobots.io", "email": "info@webrobots.io"}
    assert parse_listing_publisher(OLDER_STORE)["publisher"] == "webrobots.io"
    new = parse_listing_publisher(NEW_STORE)
    assert new["publisher"] == "Flavr Technology, LP" and new["email"] == "support@flavrtech.co"
    assert new["website"] == "https://flavrtech.co"


def _tl(*rows):
    return {"snapshots": len(rows), "timeline": [{"date": d, "publisher": p, "email": m} for d, p, m in rows]}


def test_sale_to_new_organisation_is_flagged():
    hist = _tl(("2019-06-05", "webrobots.io", "info@webrobots.io"),
               ("2024-01-31", "UAB Webrobots", "info@webrobots.io"),
               ("2025-10-02", "Paulius Jonaitis", ""),            # missing e-mail: filled from same-name entries
               ("2026-02-07", "Paulius Jonaitis", "info@webrobots.io"))
    f = ownership_findings(hist, {"publisher": "Flavr Technology, LP", "email": "support@flavrtech.co"})
    assert len(f) == 1 and f[0].rule == "pub.owner_changed" and f[0].severity == "high"
    assert "between 2026-02-07 and today" in f[0].detail and "flavrtech.co" in f[0].detail
    # Renames under the same domain are summarised, not treated as separate sales.
    assert len(f[0].evidence) == 4


def test_rename_with_same_domain_is_low():
    hist = _tl(("2020-01-01", "webrobots.io", "info@webrobots.io"), ("2024-01-01", "UAB Webrobots", "info@webrobots.io"))
    f = ownership_findings(hist, {"publisher": "UAB Webrobots", "email": "info@webrobots.io"})
    assert f[0].rule == "pub.publisher_renamed" and f[0].severity == "low"


def test_stable_history():
    hist = _tl(("2020-01-01", "Raymond Hill (gorhill)", ""), ("2023-01-01", "Raymond Hill (gorhill)", ""))
    f = ownership_findings(hist, {"publisher": "Raymond Hill (gorhill)"})
    assert f[0].rule == "pub.history_stable"


def test_no_history_no_finding():
    assert ownership_findings({"timeline": []}, {"publisher": "X"}) == []


# ------------------------------------------------------------------ disclosures --------

def test_own_words_about_collecting_urls(make_ext):
    root = make_ext({**MV3_BASE, "default_locale": "en", "background": {"service_worker": "bg.js"}},
                    {"bg.js": "1",
                     "_locales/en/messages.json":
                         '{"tip": {"message": "We use the URLs you visit to match your page to popular patterns."}}',
                     "optInHook/logo.svg": "<svg/>", "src/privacyNotice/privacyNotice.js": "1"})
    res = analyze(str(root), log=lambda *_: None)
    assert {"data.disclosed_collection", "data.consent_flow"} <= rules(res)
    f = next(f for f in res.findings if f.rule == "data.disclosed_collection")
    assert "URLs you visit" in f.evidence[0].snippet


def test_tech_logos_named_consent_are_not_a_consent_flow(make_ext):
    root = make_ext({**MV3_BASE}, {"images/icons/ConsentManager.png": "x", "images/icons/OptinMonster.svg": "<svg/>"})
    assert "data.consent_flow" not in rules(analyze(str(root), log=lambda *_: None))


def test_hidden_numeric_constants_count_as_obfuscation(make_ext):
    src = ";".join(f'const t{i}=parseInt("{21600000 + i}")' for i in range(8))
    res = analyze(str(make_ext({**MV3_BASE, "background": {"service_worker": "bg.js"}}, {"bg.js": src})), log=lambda *_: None)
    assert "code.obfuscated" in rules(res)


def test_lodash_template_compiler_is_benign(make_ext):
    src = ("var __p='';fetch('/x');var s='__p+=';try{a=new Function(s,'_',i)}catch(e){}"
           "function t(){var __p='';return __p}")
    res = analyze(str(make_ext({**MV3_BASE, "background": {"service_worker": "bg.js"}}, {"bg.js": src})), log=lambda *_: None)
    assert not rules(res) & {"code.new_function", "code.fetch_eval"}


# ------------------------------------------------------------------ lexer --------------

def test_lexer_stays_in_sync_after_regex_with_quotes():
    # A quote inside a regex used to swallow the rest of the file and hide this fetch from the scanner.
    src = 'const r = /["\']+/g; const x = a.replace(/`/g, ""); fetch("https://api.example-endpoint.io/v1");'
    js = lex("a.js", src)
    assert any(s == "https://api.example-endpoint.io/v1" for _, s in js.strings)


def test_lexer_handles_nested_template_literals_and_division():
    src = 'const a = b / c / d; const t = `x${y ? `in${z}ner` : "q"}z`; const u = "https://h.example-x.io/p";'
    js = lex("a.js", src)
    vals = [s for _, s in js.strings]
    assert "https://h.example-x.io/p" in vals and "q" in vals


def test_regex_bodies_are_not_code():
    js = lex("a.js", 'const re = /eval\\(x\\)/; ok();')
    assert "eval" not in js.code


# ------------------------------------------------------------------ web reputation -----

def test_reputation_keeps_only_sourced_claims():
    rep = _sanitise({"summary": "s", "ownership_change": {"reported": True, "detail": "sold in 2026"},
                     "concerns": [{"claim": "harvests data", "severity": "high", "url": "https://example.org/a"},
                                  {"claim": "unsourced rumour", "severity": "high", "url": "javascript:alert(1)"}],
                     "verdict": "serious_concerns"}, ["https://example.org/a", "not a url"])
    assert rep["concerns"][1]["url"] == "" and rep["sources"] == ["https://example.org/a"]
    f = reputation_findings(rep)
    assert f[0].rule == "web.reported_concerns" and f[0].confidence == "medium" and len(f[0].evidence) == 1


def test_reputation_with_nothing_found_adds_no_finding():
    assert reputation_findings(_sanitise({"summary": "nothing", "concerns": []}, [])) == []
