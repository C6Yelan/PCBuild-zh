# backend/services/chat/snapshot_redaction.py
"""Redaction helpers for chat snapshot payload persistence."""

from __future__ import annotations

import re
from typing import Any

_REDACTED = "[REDACTED]"
_SENSITIVE_FIELD_NAMES = {
    "authorization",
    "api_key",
    "x_api_key",
    "x-api-key",
    "openai_api_key",
    "gemini_api_key",
    "google_api_key",
    "ai_oai_api_key",
    "ai_api_key",
}
_BEARER_TOKEN_RE = re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]+")


def is_sensitive_snapshot_key(key: str | None) -> bool:
    if not key:
        return False
    lowered = key.strip().lower()
    return lowered in _SENSITIVE_FIELD_NAMES or "api_key" in lowered


def redact_snapshot_string(value: str, *, key: str | None = None) -> str:
    if is_sensitive_snapshot_key(key):
        return _REDACTED
    return _BEARER_TOKEN_RE.sub("Bearer [REDACTED]", value)


def redact_snapshot_value(value: Any, *, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {
            str(item_key): redact_snapshot_value(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [redact_snapshot_value(item) for item in value]
    if isinstance(value, tuple):
        return [redact_snapshot_value(item) for item in value]
    if isinstance(value, str):
        return redact_snapshot_string(value, key=key)
    if is_sensitive_snapshot_key(key):
        return _REDACTED
    return value
