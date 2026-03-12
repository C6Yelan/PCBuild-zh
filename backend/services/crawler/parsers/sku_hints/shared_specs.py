# backend/services/crawler/parsers/sku_hints/shared_specs.py
"""Low-risk shared spec parsing primitives for sku_hints extractors."""
from __future__ import annotations

import re
from collections.abc import Sequence

from .common import first_line, normalize_spaces, strip_leading_note

_LEADING_BRACKET_TAGS_RE = re.compile(r"^(?:【[^】]{1,80}】\s*)+")
_WARRANTY_NUM_RE = re.compile(r"(\d+)\s*年(?!\s*(?:版|款|版本))(?:保固|保)?")
_WARRANTY_ZH_RE = re.compile(r"([一二三四五六七八九十]+)\s*年(?!\s*(?:版|款|版本))(?:保固|保)?")

_CHINESE_NUM = {
    "一": 1,
    "二": 2,
    "三": 3,
    "四": 4,
    "五": 5,
    "六": 6,
    "七": 7,
    "八": 8,
    "九": 9,
    "十": 10,
}


def normalized_title_line(text: str) -> str:
    return normalize_spaces(strip_leading_note(first_line(text)))


def strip_leading_bracket_tags(text: str) -> str:
    return _LEADING_BRACKET_TAGS_RE.sub("", (text or "")).lstrip()


def normalize_nonempty_lines(lines: Sequence[str] | None) -> list[str]:
    out: list[str] = []
    for line in lines or []:
        line = normalize_spaces(line)
        if line:
            out.append(line)
    return out


def _parse_zh_number(raw: str) -> int | None:
    if not raw:
        return None
    if raw.isdigit():
        return int(raw)
    if raw in _CHINESE_NUM:
        return _CHINESE_NUM[raw]
    if raw.startswith("十") and len(raw) == 2 and raw[1] in _CHINESE_NUM:
        return 10 + _CHINESE_NUM[raw[1]]
    if len(raw) == 2 and raw[0] in _CHINESE_NUM and raw[1] == "十":
        return _CHINESE_NUM[raw[0]] * 10
    return None


def extract_warranty_years(texts: Sequence[str]) -> int | None:
    candidates: list[int] = []
    for text in texts:
        for m in _WARRANTY_NUM_RE.finditer(text or ""):
            candidates.append(int(m.group(1)))
        for m in _WARRANTY_ZH_RE.finditer(text or ""):
            yrs = _parse_zh_number(m.group(1))
            if yrs is not None:
                candidates.append(yrs)
    return max(candidates) if candidates else None
