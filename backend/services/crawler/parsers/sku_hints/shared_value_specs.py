# backend/services/crawler/parsers/sku_hints/shared_value_specs.py
"""Shared warranty/capacity/length primitives reused across sku_hints categories."""

from __future__ import annotations

import re
from collections.abc import Sequence

_WARRANTY_NUM_RE = re.compile(r"(\d+)\s*年(?!\s*(?:版|款|版本))(?:保固|保)?")
_WARRANTY_ZH_RE = re.compile(r"([一二三四五六七八九十]+)\s*年(?!\s*(?:版|款|版本))(?:保固|保)?")
_CAPACITY_RE = re.compile(
    r"(?i)(?<!\d)(?P<num>\d+(?:\.\d+)?)\s*(?P<unit>TB|T|GB|G)(?![A-Za-z0-9])"
)

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


def parse_zh_number(raw: str) -> int | None:
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
            yrs = parse_zh_number(m.group(1))
            if yrs is not None:
                candidates.append(yrs)
    return max(candidates) if candidates else None


def extract_warranty_years_with_registration(
    texts: Sequence[str],
    register_re: re.Pattern[str] | None = None,
) -> int | None:
    candidates: list[int] = []
    base = extract_warranty_years(texts)
    if base is not None:
        candidates.append(base)
    if register_re is not None:
        for text in texts:
            for m in register_re.finditer(text or ""):
                candidates.append(int(m.group(1)) + int(m.group(2)))
    return max(candidates) if candidates else None


def extract_limit_hint(texts: Sequence[str], limit_re: re.Pattern[str]) -> str | None:
    for text in texts:
        m = limit_re.search(text or "")
        if m:
            return m.group(1)
    return None


def extract_capacity_gib(text: str) -> int | None:
    m = _CAPACITY_RE.search(text or "")
    if not m:
        return None
    num = float(m.group("num"))
    unit = m.group("unit").upper()
    if unit in ("T", "TB"):
        bytes_val = num * 10**12
    else:
        bytes_val = num * 10**9
    return int(round(bytes_val / (1 << 30)))


def normalize_length_mm(
    value: float,
    unit: str | None,
    *,
    assume_cm_threshold: float = 80,
) -> int:
    if unit == "mm":
        return int(round(value))
    if unit in ("cm", "公分"):
        return int(round(value * 10))
    if value <= assume_cm_threshold:
        return int(round(value * 10))
    return int(round(value))
