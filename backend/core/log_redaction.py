# backend/core/log_redaction.py
"""Shared sensitive-field and redaction primitives for core logging."""

from __future__ import annotations

from collections.abc import Mapping, Set as AbstractSet
from typing import Any

from backend.core.sensitive_redaction_policy import (
    SHARED_SENSITIVE_KEY_NAMES,
    matches_sensitive_key,
)

REDACTED = "[REDACTED]"

DEFAULT_SENSITIVE_LOG_KEYS = SHARED_SENSITIVE_KEY_NAMES | {
    "password",
    "token",
    "access_token",
    "refresh_token",
    "public_token",
    "token_hash",
    "csrf_token",
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
    return matches_sensitive_key(key, sensitive_keys=sensitive_keys)


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
