"""Settings: a simple config.json, with optional environment-variable and command-line overrides.

Where Dossier looks for config.json (first one found wins):
  1. --config PATH
  2. next to the dossier executable (standalone binaries ship with one)
  3. the folder Dossier is run from as source (the repository root)
  4. ~/.dossier/config.json

Precedence for each setting: command-line flag > environment variable > config.json > default.
Environment variables (optional, for scripting): OPENAI_API_KEY, DOSSIER_LLM_API_KEY, DOSSIER_LLM_BASE_URL,
DOSSIER_LLM_MODEL, DOSSIER_LLM_TIMEOUT, DOSSIER_LLM_JSON_MODE.
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_MODEL = "gpt-5.4-mini"
CONFIG_NAME = "config.json"

TEMPLATE = """{
  // Dossier settings. Lines starting with // are comments.
  // Leave a value as "" if you don't use it. Keep this file private: it holds your API key.

  // ---- Option A: OpenAI ------------------------------------------------------------
  // Paste your key between the quotes (it starts with sk-).
  // Create one at https://platform.openai.com/api-keys
  "openai_api_key": "",

  // Which model to use. The default is a good, cheap choice for OpenAI (~1 cent per extension).
  "model": "gpt-5.4-mini",

  // ---- Option B: a local model instead (nothing leaves your machine) -----------------
  // Set base_url to your local server and change "model" above to your local model's name.
  //   Ollama:     "http://localhost:11434/v1"   (model e.g. "qwen2.5-coder:14b")
  //   LM Studio:  "http://localhost:1234/v1"    (model = the name shown in LM Studio)
  "base_url": "",

  // Only for other hosted OpenAI-compatible services (e.g. OpenRouter). Local servers don't need it.
  "api_key": "",

  // ---- Extra checks (both on by default) ----------------------------------------------
  // Look up who published the extension in the past, using archived store pages (web.archive.org).
  // Catches extensions that were sold to a new owner.
  "archive_lookup": true,
  // With OpenAI only: search the web for news and security write-ups about the extension (~2 cents each).
  "web_reputation": true,

  // ---- Advanced ----------------------------------------------------------------------
  "timeout_seconds": 180,
  "json_mode": true
}
"""

KNOWN_KEYS = {"openai_api_key", "model", "base_url", "api_key", "timeout_seconds", "json_mode",
              "archive_lookup", "web_reputation"}


class ConfigError(Exception):
    pass


def _app_dir() -> Path:
    """Folder of the executable (standalone build) or the repository root (source checkout)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def user_config_path() -> Path:
    return Path.home() / ".dossier" / CONFIG_NAME


def candidate_paths() -> list[Path]:
    return [_app_dir() / CONFIG_NAME, user_config_path()]


def default_init_path() -> Path:
    """Where --init-config writes when no path is given: next to Dossier if writable, else the user folder."""
    d = _app_dir()
    if os.access(d, os.W_OK) and (getattr(sys, "frozen", False) or (d / "pyproject.toml").is_file()):
        return d / CONFIG_NAME
    return user_config_path()


def _strip_comments(text: str) -> str:
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i) or c == "#":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))   # tolerate trailing commas


def read_config_file(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as e:
        raise ConfigError(f"Can't read {path}: {e}") from e
    try:
        data = json.loads(_strip_comments(text))
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path} is not valid: {e.msg} (line {e.lineno}, column {e.colno}). "
                          "Check for a missing comma or quote.") from e
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain {{ ... }} settings.")
    unknown = set(data) - KNOWN_KEYS
    if unknown:
        print(f"warning: {path}: ignoring unknown setting(s): {', '.join(sorted(unknown))}", file=sys.stderr)
    return data


def load_config(explicit: Path | None = None) -> tuple[dict, Path | None]:
    if explicit:
        if not explicit.is_file():
            raise ConfigError(f"Config file not found: {explicit}")
        return read_config_file(explicit), explicit
    for p in candidate_paths():
        if p.is_file():
            return read_config_file(p), p
    return {}, None


def write_template(path: Path) -> Path:
    if path.exists():
        raise ConfigError(f"{path} already exists; not overwriting it.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(TEMPLATE, encoding="utf-8")
    return path


@dataclass
class LLMConfig:
    enabled: bool
    base_url: str | None
    model: str
    api_key: str | None
    timeout: float
    json_mode: bool
    source: str = ""                       # which config file was used, for messages
    notes: list[str] = field(default_factory=list)

    @property
    def provider_label(self) -> str:
        if not self.base_url:
            return "OpenAI"
        u = self.base_url.lower()
        if ":11434" in u or "ollama" in u:
            return "Ollama (local)"
        if ":1234" in u or "lmstudio" in u:
            return "LM Studio (local)"
        if "localhost" in u or "127.0.0.1" in u:
            return "Local OpenAI-compatible server"
        return f"OpenAI-compatible ({self.base_url})"

    @property
    def is_local(self) -> bool:
        return bool(self.base_url) and any(h in self.base_url for h in ("localhost", "127.0.0.1", "[::1]", "0.0.0.0"))


def _s(v) -> str:
    return str(v).strip() if v not in (None, False) else ""


def llm_config(no_llm: bool = False, model: str | None = None, base_url: str | None = None,
               file_cfg: dict | None = None, source: Path | None = None) -> LLMConfig:
    fc = file_cfg or {}
    env = os.environ.get
    base = base_url or env("DOSSIER_LLM_BASE_URL") or _s(fc.get("base_url")) or None
    if base:
        key = env("DOSSIER_LLM_API_KEY") or _s(fc.get("api_key")) or env("OPENAI_API_KEY") or _s(fc.get("openai_api_key"))
        if not key:
            key = "not-needed"   # local servers ignore the key but the client library requires one
    else:
        key = env("DOSSIER_LLM_API_KEY") or env("OPENAI_API_KEY") or _s(fc.get("openai_api_key")) or _s(fc.get("api_key"))
    jm = env("DOSSIER_LLM_JSON_MODE")
    try:
        timeout = float(env("DOSSIER_LLM_TIMEOUT") or fc.get("timeout_seconds") or 180)
    except (TypeError, ValueError):
        timeout = 180.0
    return LLMConfig(
        enabled=not no_llm and bool(key),
        base_url=base,
        model=model or env("DOSSIER_LLM_MODEL") or _s(fc.get("model")) or DEFAULT_MODEL,
        api_key=key or None,
        timeout=timeout,
        json_mode=(jm != "0") if jm is not None else bool(fc.get("json_mode", True)),
        source=str(source) if source else "",
    )
