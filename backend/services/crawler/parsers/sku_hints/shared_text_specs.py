# backend/services/crawler/parsers/sku_hints/shared_text_specs.py
"""Shared text/model primitives reused across sku_hints categories."""

from __future__ import annotations

import re
from collections.abc import Sequence, Set as AbstractSet

from .common import first_line, head_before_brackets, normalize_spaces, strip_leading_note

_LEADING_BRACKET_TAGS_RE = re.compile(r"^(?:【[^】]{1,80}】\s*)+")
_HEAD_SLASH_SPLIT_RE = re.compile(r"[／/|｜]")
_HEAD_PUNCT_SPLIT_RE = re.compile(r"[，,、:：]")
_BRAND_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]{1,}")
_CJK_BRAND_PREFIX_RE = re.compile(r"^([\u4e00-\u9fff]{1,20})")


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
