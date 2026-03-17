from __future__ import annotations

import re

from ..common import first_line, head_before_brackets, normalize_spaces, strip_leading_note
from ..shared_specs import normalized_title_line

_BRACKET_CONTENT_RE = re.compile(r"[（(【\[](?P<content>[^）)】\]]+)[）)】\]]")
_BRACKET_REMOVE_RE = re.compile(r"[（(【\[][^\)）】\]]*[）)】\]]")
_SKU_TOKEN_RE = re.compile(r"[A-Z0-9][A-Z0-9-]{4,}", flags=re.IGNORECASE)
_PLUS_SPLIT_RE = re.compile(r"[+＋]")
_SPEC_TOKEN_RE = re.compile(
    r"(?i)^(?:\d{3,4}G(?:B)?|\d+(?:\.\d+)?T(?:B)?|GEN[345]|PCI-?E|NVME|SATA|M\.2)$"
)
_BRAND_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:\bACER\b|宏碁)", flags=re.IGNORECASE), "ACER"),
    (re.compile(r"(?:\bSAMSUNG\b|三星)", flags=re.IGNORECASE), "SAMSUNG"),
    (re.compile(r"(?:\bKINGSTON\b|金士頓)", flags=re.IGNORECASE), "KINGSTON"),
    (re.compile(r"(?:\bCRUCIAL\b|美光)", flags=re.IGNORECASE), "CRUCIAL"),
    (re.compile(r"(?:\bADATA\b|威剛)", flags=re.IGNORECASE), "ADATA"),
    (re.compile(r"(?:\bKIOXIA\b|鎧俠|東芝)", flags=re.IGNORECASE), "KIOXIA"),
    (re.compile(r"(?:\bWD\b|WESTERN\s*DIGITAL|威騰)", flags=re.IGNORECASE), "WD"),
    (re.compile(r"(?:\bSEAGATE\b|希捷)", flags=re.IGNORECASE), "SEAGATE"),
    (re.compile(r"(?i)\bCORSAIR\b|海盜船"), "CORSAIR"),
    (re.compile(r"(?i)\bMSI\b|微星"), "MSI"),
    (re.compile(r"(?i)\bTEAMGROUP\b|\bTEAM\s*GROUP\b|\bT-?FORCE\b|十銓"), "TEAMGROUP"),
    (re.compile(r"(?i)\bZHITAI\b|致鈦|致態|致态"), "ZHITAI"),
]


def _looks_like_model(token: str) -> bool:
    if not token or len(token) < 5:
        return False
    if _SPEC_TOKEN_RE.match(token):
        return False
    has_alpha = any(ch.isalpha() for ch in token)
    has_digit = any(ch.isdigit() for ch in token)
    return has_alpha and has_digit


def extract_ssd_bracket_model(text: str) -> str | None:
    for match in _BRACKET_CONTENT_RE.finditer(text or ""):
        content = match.group("content") or ""
        for raw in re.split(r"[\s,;/|]+", content):
            token = raw.strip().strip("()[]{}")
            if _looks_like_model(token):
                return token
    return None


def infer_ssd_brand(text: str) -> str | None:
    if not text:
        return None
    for pattern, normalized in _BRAND_PATTERNS:
        if pattern.search(text):
            return normalized
    match = re.match(r"[A-Za-z][A-Za-z0-9-]*", text.strip())
    if match:
        return match.group(0).upper()
    return None


def clean_ssd_model(text: str, brand_hint: str | None) -> str | None:
    line = normalize_spaces(strip_leading_note(first_line(text)))
    base = head_before_brackets(line) or line
    base = _BRACKET_REMOVE_RE.sub(" ", base)
    base = _PLUS_SPLIT_RE.split(base, 1)[0].strip()
    if brand_hint:
        base = re.sub(re.escape(brand_hint), " ", base, flags=re.IGNORECASE)
    base = normalize_spaces(base).strip(" -_/|")
    return base or None


def extract_ssd_sku_hint(title: str) -> str | None:
    line = normalized_title_line(title)
    hint = extract_ssd_bracket_model(line)
    if hint:
        return hint
    for match in _SKU_TOKEN_RE.finditer(line or ""):
        token = match.group(0)
        if _looks_like_model(token):
            return token
    return clean_ssd_model(line, None)
