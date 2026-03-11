# backend/core/logfmt.py
"""Shared logfmt formatting primitives for core logging."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any


def quote_logfmt_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def needs_logfmt_quotes(value: str, *, quote_mode: str = "space") -> bool:
    if quote_mode == "whitespace":
        return any(char in value for char in ('=', '"')) or any(char.isspace() for char in value)
    if quote_mode == "space":
        return any(char in value for char in (' ', '"', '='))
    raise ValueError("quote_mode 只能是 'space' 或 'whitespace'")


def format_logfmt_value(
    value: Any,
    *,
    structured_json: bool = False,
    quote_mode: str = "space",
) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)

    if structured_json and isinstance(value, (dict, list)):
        return quote_logfmt_string(
            json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        )

    text = str(value)
    return quote_logfmt_string(text) if needs_logfmt_quotes(text, quote_mode=quote_mode) else text


def render_logfmt_fields(
    fields: Mapping[str, Any],
    *,
    structured_json: bool = False,
    quote_mode: str = "space",
    skip_none: bool = False,
) -> str:
    parts: list[str] = []
    for key in sorted(fields.keys()):
        value = fields[key]
        if skip_none and value is None:
            continue
        parts.append(
            f"{key}={format_logfmt_value(value, structured_json=structured_json, quote_mode=quote_mode)}"
        )
    return " ".join(parts)


def render_logfmt_pairs(
    pairs: Sequence[tuple[str, Any]],
    *,
    structured_json: bool = False,
    quote_mode: str = "space",
    skip_none: bool = False,
) -> str:
    parts: list[str] = []
    for key, value in pairs:
        if skip_none and value is None:
            continue
        parts.append(
            f"{key}={format_logfmt_value(value, structured_json=structured_json, quote_mode=quote_mode)}"
        )
    return " ".join(parts)
