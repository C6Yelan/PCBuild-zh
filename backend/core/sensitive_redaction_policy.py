# backend/core/sensitive_redaction_policy.py
"""Shared sensitive-key policy primitives for snapshot and logging redaction."""
from __future__ import annotations

import re
from collections.abc import Set as AbstractSet

SHARED_SENSITIVE_KEY_NAMES = frozenset(
    {
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
)
SNAPSHOT_SENSITIVE_KEY_FRAGMENTS = ("api_key",)

_BEARER_TOKEN_RE = re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]+")


def normalize_sensitive_key(key: str | None) -> str:
    if not key:
        return ""
    return key.strip().lower()


def matches_sensitive_key(
    key: str | None,
    *,
    sensitive_keys: AbstractSet[str],
    contains_fragments: tuple[str, ...] = (),
) -> bool:
    lowered = normalize_sensitive_key(key)
    if not lowered:
        return False
    return lowered in sensitive_keys or any(fragment in lowered for fragment in contains_fragments)


def redact_bearer_token(value: str, *, redacted: str = "[REDACTED]") -> str:
    return _BEARER_TOKEN_RE.sub(f"Bearer {redacted}", value)
