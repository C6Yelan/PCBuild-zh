# backend/core/log_redaction.py
"""Shared sensitive-field and redaction primitives for core logging."""

from __future__ import annotations

from collections.abc import Mapping, Set as AbstractSet
from typing import Any

REDACTED = "[REDACTED]"

DEFAULT_SENSITIVE_LOG_KEYS = {
    "password",
    "token",
    "access_token",
    "api_key",
    "x_api_key",
    "x-api-key",
    "openai_api_key",
    "gemini_api_key",
    "google_api_key",
    "ai_oai_api_key",
    "ai_api_key",
    "refresh_token",
    "public_token",
    "token_hash",
    "csrf_token",
    "authorization",
    "cookie",
    "set_cookie",
    "session",
    "session_id",
}


def is_sensitive_log_key(
    key: str | None,
    *,
    sensitive_keys: AbstractSet[str] = DEFAULT_SENSITIVE_LOG_KEYS,
) -> bool:
    if not key:
        return False
    return key.strip().lower() in sensitive_keys


def redact_log_value(
    value: Any,
    *,
    key: str | None = None,
    sensitive_keys: AbstractSet[str] = DEFAULT_SENSITIVE_LOG_KEYS,
    redacted: str = REDACTED,
) -> Any:
    if is_sensitive_log_key(key, sensitive_keys=sensitive_keys):
        return redacted
    return value


def redact_log_mapping(
    fields: Mapping[str, Any],
    *,
    sensitive_keys: AbstractSet[str] = DEFAULT_SENSITIVE_LOG_KEYS,
    redacted: str = REDACTED,
    mode: str = "drop",
) -> dict[str, Any]:
    if mode == "drop":
        return {
            key: value
            for key, value in fields.items()
            if not is_sensitive_log_key(key, sensitive_keys=sensitive_keys)
        }
    if mode == "replace":
        return {
            key: redact_log_value(
                value,
                key=key,
                sensitive_keys=sensitive_keys,
                redacted=redacted,
            )
            for key, value in fields.items()
        }
    raise ValueError("mode 只能是 'drop' 或 'replace'")
