# backend/services/crawler/parsers/sku_hints/common.py
from __future__ import annotations

import re

_BRACKET_SPLIT_RE = re.compile(r"[（(【]")
_SPACE_RE = re.compile(r"\s+")
_LEADING_NOTE_RE = re.compile(r"^\[[^\]]+\]\s*")


def first_line(text: str) -> str:
    if not text:
        return ""
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return text.strip()


def normalize_spaces(text: str) -> str:
    return _SPACE_RE.sub(" ", (text or "")).strip()


def head_before_brackets(text: str) -> str:
    head = _BRACKET_SPLIT_RE.split(text or "", 1)[0]
    return normalize_spaces(head)


def strip_leading_note(text: str) -> str:
    return _LEADING_NOTE_RE.sub("", (text or "")).strip()


def compact_extra(extra: dict[str, object] | None) -> dict[str, object]:
    if not extra:
        return {}
    return {k: v for k, v in extra.items() if v is not None}
