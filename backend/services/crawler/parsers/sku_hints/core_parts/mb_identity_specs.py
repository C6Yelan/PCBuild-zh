from __future__ import annotations

import re

from ..common import first_line, head_before_brackets, normalize_spaces

_BRAND_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:\bASUS\b|華碩)", flags=re.IGNORECASE), "ASUS"),
    (re.compile(r"(?:\bMSI\b|微星)", flags=re.IGNORECASE), "MSI"),
    (re.compile(r"(?:\bGIGABYTE\b|技嘉)", flags=re.IGNORECASE), "GIGABYTE"),
    (re.compile(r"(?:\bASROCK\b|華擎)", flags=re.IGNORECASE), "ASRock"),
    (re.compile(r"(?:\bBIOSTAR\b|映泰)", flags=re.IGNORECASE), "BIOSTAR"),
]
_STOPWORDS = {
    "ATX",
    "M-ATX",
    "MATX",
    "MICRO",
    "E-ATX",
    "ITX",
    "MINI-ITX",
    "CEB",
    "EEB",
    "DDR4",
    "DDR5",
    "WIFI6",
    "WIFI6E",
    "WIFI7",
    "LAN",
    "RGB",
    "ARGB",
}
_VARIANT_ALIASES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\bBTF\b"), "BTF"),
    (re.compile(r"(?i)\bPROJECT\s*ZERO\b"), "PZ"),
    (re.compile(r"(?i)\bPZ\b"), "PZ"),
    (re.compile(r"(?i)\bSTEALTH\b"), "STEALTH"),
]


def infer_mb_brand_hint(title: str) -> str | None:
    text = (title or "").strip()
    if not text:
        return None
    for pattern, normalized in _BRAND_PATTERNS:
        if pattern.search(text):
            return normalized
    return None


def extract_mb_head(title: str) -> str:
    line = first_line(title)
    if not line:
        return ""
    return normalize_spaces(head_before_brackets(line))


def extract_mb_sku_model_hint(title: str) -> str | None:
    if not title:
        return None
    head = extract_mb_head(title)
    variant: str | None = None
    for pattern, normalized in _VARIANT_ALIASES:
        if pattern.search(head):
            variant = normalized
            break
    tokens = [token for token in head.split(" ") if token]
    idx = None
    for i, token in enumerate(tokens):
        if any(ch.isdigit() for ch in token):
            idx = i
            break
    if idx is None:
        return variant
    picked: list[str] = []
    for token in tokens[idx:]:
        token = token.strip().strip(",/")
        if token.upper() in _STOPWORDS or len(token) > 18:
            break
        picked.append(token)
        if len(picked) >= 4:
            break
    base = " ".join(picked).strip()
    if not base:
        return variant
    if variant and variant not in base.upper():
        return f"{base} {variant}"
    return base
