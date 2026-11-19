"""config.json: the beginner-friendly way to set the API key and model."""
import json

import pytest

from dossier import config as C
from dossier.cli import main

ENV = ("OPENAI_API_KEY", "DOSSIER_LLM_API_KEY", "DOSSIER_LLM_BASE_URL", "DOSSIER_LLM_MODEL",
       "DOSSIER_LLM_TIMEOUT", "DOSSIER_LLM_JSON_MODE")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in ENV:
        monkeypatch.delenv(k, raising=False)


def test_template_parses_and_is_disabled_until_key_added(tmp_path):
    p = C.write_template(tmp_path / "config.json")
    data = C.read_config_file(p)
    assert data["model"] == C.DEFAULT_MODEL and data["openai_api_key"] == ""
    assert not C.llm_config(file_cfg=data).enabled


def test_key_from_config_file(tmp_path):
    data = {"openai_api_key": "sk-from-file", "model": "gpt-x"}
    c = C.llm_config(file_cfg=data)
    assert c.enabled and c.api_key == "sk-from-file" and c.model == "gpt-x" and c.provider_label == "OpenAI"


def test_local_model_from_config_needs_no_key():
    c = C.llm_config(file_cfg={"base_url": "http://localhost:11434/v1", "model": "qwen2.5-coder:14b"})
    assert c.enabled and c.is_local and c.provider_label.startswith("Ollama") and c.model == "qwen2.5-coder:14b"


def test_precedence_flag_over_env_over_file(monkeypatch):
    data = {"openai_api_key": "sk-file", "model": "file-model"}
    monkeypatch.setenv("DOSSIER_LLM_MODEL", "env-model")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-env")
    c = C.llm_config(file_cfg=data)
    assert (c.model, c.api_key) == ("env-model", "sk-env")
    assert C.llm_config(file_cfg=data, model="flag-model").model == "flag-model"


def test_forgiving_syntax_and_clear_errors(tmp_path):
    p = tmp_path / "config.json"
    p.write_text('{\n  // comment\n  "openai_api_key": "sk-1", # also a comment\n  "model": "m",\n}\n', encoding="utf-8")
    assert C.read_config_file(p)["model"] == "m"
    p.write_text('{\n  "openai_api_key": "sk-1"\n  "model": "m"\n}', encoding="utf-8")
    with pytest.raises(C.ConfigError, match="line 3"):
        C.read_config_file(p)


def test_urls_with_hash_and_slashes_survive(tmp_path):
    p = tmp_path / "config.json"
    p.write_text('{"base_url": "http://host:1234/v1#x//y"}', encoding="utf-8")
    assert C.read_config_file(p)["base_url"] == "http://host:1234/v1#x//y"


def test_cli_init_config_and_use(tmp_path, make_ext, capsys):
    cfgp = tmp_path / "my.json"
    assert main(["--init-config", str(cfgp)]) == 0
    assert main(["--init-config", str(cfgp)]) == 1           # never overwrites
    root = make_ext({"manifest_version": 3, "name": "X", "version": "1"}, {})
    assert main([str(root), "--config", str(cfgp), "-o", str(tmp_path / "r"), "--no-history"]) == 0
    err = capsys.readouterr().err
    assert "No AI key set" in err and str(cfgp) in err
    cfgp.write_text("{ broken", encoding="utf-8")
    assert main([str(root), "--config", str(cfgp), "-o", str(tmp_path / "r")]) == 1


def test_config_never_leaks_into_reports(tmp_path, make_ext):
    cfgp = tmp_path / "c.json"
    cfgp.write_text(json.dumps({"base_url": "http://localhost:9/v1", "api_key": "sk-SECRET-123"}), encoding="utf-8")
    root = make_ext({"manifest_version": 3, "name": "X", "version": "1"}, {})
    main([str(root), "--config", str(cfgp), "-o", str(tmp_path / "r"), "--no-llm", "--json", "-q"])
    for f in (tmp_path / "r").rglob("*"):
        if f.is_file():
            assert "sk-SECRET-123" not in f.read_text(encoding="utf-8", errors="ignore")
