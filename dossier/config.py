"""Configuration from environment variables and an optional .env file.

LLM settings (all optional):
  DOSSIER_LLM_BASE_URL   OpenAI-compatible endpoint. Unset = OpenAI.
                          Ollama:     http://localhost:11434/v1
                          LM Studio:  http://localhost:1234/v1
  DOSSIER_LLM_MODEL      Model name (default gpt-5.4-mini; e.g. "qwen2.5-coder:14b" for Ollama)
  DOSSIER_LLM_API_KEY    API key for the endpoint. Falls back to OPENAI_API_KEY.
                          Local servers usually accept any non-empty value.
  DOSSIER_LLM_TIMEOUT    Seconds (default 180).
  DOSSIER_LLM_JSON_MODE  "1" (default) to request JSON mode; set "0" for servers that reject it.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_MODEL = "gpt-5.4-mini"


def load_dotenv(path: Path | None = None) -> None:
    """Minimal .env loader (no dependency). Existing environment variables win."""
    candidates = [Path.cwd() / ".env", Path(__file__).resolve().parent.parent / ".env"]
    if getattr(sys, "frozen", False):                      # standalone binary: also look next to the executable
        candidates.insert(1, Path(sys.executable).resolve().parent / ".env")
    for p in [path] if path else candidates:
        if not p or not p.is_file():
            continue
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip().removeprefix("export ").strip()
            v = v.strip().strip('"').strip("'")
            os.environ.setdefault(k, v)
        break


@dataclass
class LLMConfig:
    enabled: bool
    base_url: str | None
    model: str
    api_key: str | None
    timeout: float
    json_mode: bool

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


def llm_config(no_llm: bool = False, model: str | None = None, base_url: str | None = None) -> LLMConfig:
    base = base_url or os.environ.get("DOSSIER_LLM_BASE_URL") or None
    key = os.environ.get("DOSSIER_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if base and not key:
        key = "not-needed"  # local servers ignore the key but the client requires one
    enabled = not no_llm and bool(key)
    return LLMConfig(
        enabled=enabled,
        base_url=base,
        model=model or os.environ.get("DOSSIER_LLM_MODEL") or DEFAULT_MODEL,
        api_key=key,
        timeout=float(os.environ.get("DOSSIER_LLM_TIMEOUT", "180")),
        json_mode=os.environ.get("DOSSIER_LLM_JSON_MODE", "1") != "0",
    )
