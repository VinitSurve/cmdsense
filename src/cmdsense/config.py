"""Configuration schema for cmdsense (stored in this tool's own config directory)."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from cmdsense.common.config import ConfigSchema, Field

_ENV_VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_RAW_SECRET_PREFIXES = (
    "sk-",
    "sk_live_",
    "sk_test_",
    "ghp_",
    "gho_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "AIza",
    "glpat-",
    "Bearer ",
)


def _validate_endpoint(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return "Endpoint URL must not be empty."
    parsed = urlparse(value.strip())
    if parsed.scheme not in ("http", "https"):
        return "Endpoint URL must use http:// or https:// scheme."
    if not parsed.hostname:
        return "Endpoint URL must include a valid hostname."
    return None


def _validate_api_key_env(value: Any) -> str | None:
    if not isinstance(value, str):
        return "Expected an environment variable name string."
    stripped = value.strip()
    if not stripped:
        return None
    if any(stripped.startswith(prefix) for prefix in _RAW_SECRET_PREFIXES):
        return (
            "Provide the name of an environment variable (e.g. OPENAI_API_KEY), "
            "never the raw secret key itself."
        )
    if not _ENV_VAR_RE.match(stripped):
        return (
            "Must be a valid environment variable identifier (letters, digits, underscores, "
            "starting with a letter or underscore), e.g. OPENAI_API_KEY."
        )
    return None


def _validate_model(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return "Model identifier must not be empty."
    return None


SCHEMA = ConfigSchema(
    {
        "ai_enabled": Field(
            "bool",
            False,
            "Enable optional AI backend when --ai is passed on a command.",
        ),
        "ai_provider": Field(
            "str",
            "none",
            "Optional AI backend provider (none, ollama, openai-compatible).",
            choices=("none", "ollama", "openai-compatible"),
        ),
        "ai_endpoint": Field(
            "str",
            "http://localhost:11434",
            "Base URL of the AI API endpoint (default is local Ollama).",
            validator=_validate_endpoint,
        ),
        "ai_model": Field(
            "str",
            "llama3.2",
            "Model identifier requested from the AI provider.",
            validator=_validate_model,
        ),
        "ai_api_key_env": Field(
            "str",
            "OPENAI_API_KEY",
            "Name of the environment variable holding the API key (never the key itself).",
            validator=_validate_api_key_env,
        ),
        "ai_timeout": Field(
            "float",
            15.0,
            "Timeout in seconds for optional AI HTTP requests.",
            minimum=1.0,
            maximum=120.0,
        ),
        "ai_send_confirmed": Field(
            "bool",
            False,
            "Explicitly confirm sending redacted command/error text to a non-loopback endpoint.",
        ),
    }
)
