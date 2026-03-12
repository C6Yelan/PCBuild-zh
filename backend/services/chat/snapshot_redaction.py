# backend/services/chat/snapshot_redaction.py
"""Redaction helpers for chat snapshot payload persistence."""

from __future__ import annotations

from typing import Any

from backend.core.sensitive_redaction_policy import (
    SHARED_SENSITIVE_KEY_NAMES,
    SNAPSHOT_SENSITIVE_KEY_FRAGMENTS,
    matches_sensitive_key,
    redact_bearer_token,
)

_REDACTED = "[REDACTED]"
_SENSITIVE_FIELD_NAMES = SHARED_SENSITIVE_KEY_NAMES


def is_sensitive_snapshot_key(key: str | None) -> bool:
    return matches_sensitive_key(
        key,
        sensitive_keys=_SENSITIVE_FIELD_NAMES,
        contains_fragments=SNAPSHOT_SENSITIVE_KEY_FRAGMENTS,
    )


def redact_snapshot_string(value: str, *, key: str | None = None) -> str:
    if is_sensitive_snapshot_key(key):
        return _REDACTED
    return redact_bearer_token(value, redacted=_REDACTED)


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
