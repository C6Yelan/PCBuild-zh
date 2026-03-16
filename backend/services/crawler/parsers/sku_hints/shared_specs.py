# backend/services/crawler/parsers/sku_hints/shared_specs.py
"""Low-risk shared spec parsing primitives for sku_hints extractors."""
from __future__ import annotations

import re
from collections.abc import Sequence, Set as AbstractSet

from .common import first_line, head_before_brackets, normalize_spaces, strip_leading_note

_LEADING_BRACKET_TAGS_RE = re.compile(r"^(?:【[^】]{1,80}】\s*)+")
_WARRANTY_NUM_RE = re.compile(r"(\d+)\s*年(?!\s*(?:版|款|版本))(?:保固|保)?")
_WARRANTY_ZH_RE = re.compile(r"([一二三四五六七八九十]+)\s*年(?!\s*(?:版|款|版本))(?:保固|保)?")
_HEAD_SLASH_SPLIT_RE = re.compile(r"[／/|｜]")
_HEAD_PUNCT_SPLIT_RE = re.compile(r"[，,、:：]")
_BRAND_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]{1,}")
_CJK_BRAND_PREFIX_RE = re.compile(r"^([\u4e00-\u9fff]{1,20})")
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


def normalized_title_line(text: str) -> str:
    return normalize_spaces(strip_leading_note(first_line(text)))


def strip_leading_bracket_tags(text: str) -> str:
    return _LEADING_BRACKET_TAGS_RE.sub("", (text or "")).lstrip()


def normalize_nonempty_lines(
    lines: Sequence[str] | None,
    *,
    skip_substrings: Sequence[str] | None = None,
) -> list[str]:
    out: list[str] = []
    for line in lines or []:
        line = normalize_spaces(line)
        if skip_substrings and any(token in line for token in skip_substrings):
            continue
        if line:
            out.append(line)
    return out


def build_title_desc_texts(
    title: str,
    desc_lines: Sequence[str] | None,
    *,
    skip_substrings: Sequence[str] | None = None,
) -> tuple[str, list[str], list[str]]:
    line = normalized_title_line(title)
    desc = normalize_nonempty_lines(desc_lines, skip_substrings=skip_substrings)
    return line, desc, [line] + desc


def extract_model_head(
    text: str,
    *,
    strip_bracket_tags: bool = False,
    bundle_split_re: re.Pattern[str] | None = None,
    clean_pattern: re.Pattern[str] | None = None,
) -> str:
    head = text or ""
    if strip_bracket_tags:
        head = strip_leading_bracket_tags(head)
    head = head_before_brackets(head) or head
    if bundle_split_re is not None:
        head = bundle_split_re.split(head, 1)[0]
    head = _HEAD_SLASH_SPLIT_RE.split(head, 1)[0]
    head = _HEAD_PUNCT_SPLIT_RE.split(head, 1)[0]
    if clean_pattern is not None:
        head = clean_pattern.sub(" ", head)
    return normalize_spaces(head)


def extract_model_hint(
    text: str,
    *,
    strip_bracket_tags: bool = False,
    bundle_split_re: re.Pattern[str] | None = None,
    clean_pattern: re.Pattern[str] | None = None,
) -> str | None:
    head = extract_model_head(
        text,
        strip_bracket_tags=strip_bracket_tags,
        bundle_split_re=bundle_split_re,
        clean_pattern=clean_pattern,
    )
    return head or None


def extract_brand_hint(
    text: str,
    *,
    prefix_rules: Sequence[tuple[re.Pattern[str], str]] | None = None,
    ignore_tokens: AbstractSet[str] | None = None,
    strip_bracket_tags: bool = False,
    allow_cjk_prefix: bool = False,
) -> str | None:
    clean = strip_leading_bracket_tags(text) if strip_bracket_tags else (text or "")
    head = clean.strip()
    for pat, norm in prefix_rules or ():
        if pat.search(head):
            return norm
    if allow_cjk_prefix:
        m = _CJK_BRAND_PREFIX_RE.match(head)
        if m:
            return m.group(1)
    for m in _BRAND_TOKEN_RE.finditer(clean):
        token = m.group(0).upper()
        if ignore_tokens and token in ignore_tokens:
            continue
        return token
    return None


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
