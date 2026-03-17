# backend/core/log_event_lines.py
"""Shared event-line formatting primitives for security and pipeline logging."""

from __future__ import annotations

from collections.abc import Mapping, Sequence, Set as AbstractSet
from typing import Any

from backend.core.log_redaction import (
    DEFAULT_SENSITIVE_LOG_KEYS,
    redact_log_mapping,
)
from backend.core.logfmt import render_logfmt_pairs


def apply_log_field_policy(
    fields: Mapping[str, Any],
    *,
    default_fields: Mapping[str, Any] | None = None,
    sensitive_keys: AbstractSet[str] = DEFAULT_SENSITIVE_LOG_KEYS,
    redaction_mode: str | None = None,
) -> dict[str, Any]:
    safe_fields: dict[str, Any] = dict(fields)
    if redaction_mode is not None:
        safe_fields = redact_log_mapping(
            safe_fields,
            sensitive_keys=sensitive_keys,
            mode=redaction_mode,
        )
    if default_fields:
        for key, value in default_fields.items():
            safe_fields.setdefault(key, value)
    return safe_fields


def build_log_event_message(
    *,
    prefix_pairs: Sequence[tuple[str, Any]],
    fields: Mapping[str, Any],
    default_fields: Mapping[str, Any] | None = None,
    sensitive_keys: AbstractSet[str] = DEFAULT_SENSITIVE_LOG_KEYS,
    redaction_mode: str | None = None,
    structured_json: bool = False,
    quote_mode: str = "space",
    skip_none: bool = False,
) -> str:
    safe_fields = apply_log_field_policy(
        fields,
        default_fields=default_fields,
        sensitive_keys=sensitive_keys,
        redaction_mode=redaction_mode,
    )
    pairs = list(prefix_pairs)
    for key in sorted(safe_fields.keys()):
        pairs.append((key, safe_fields[key]))
    return render_logfmt_pairs(
        pairs,
        structured_json=structured_json,
        quote_mode=quote_mode,
        skip_none=skip_none,
    )
