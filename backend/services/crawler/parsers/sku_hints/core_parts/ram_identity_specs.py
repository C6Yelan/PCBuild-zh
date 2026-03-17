from __future__ import annotations

import re

from ..common import first_line, normalize_spaces, strip_leading_note

_BRACKET_CONTENT_RE = re.compile(r"[（(【\[](?P<content>[^）)】\]]+)[）)】\]]")
_BRACKET_REMOVE_RE = re.compile(r"[（(【\[][^\)）】\]]*[）)】\]]")
_SKU_TOKEN_RE = re.compile(r"[A-Z0-9][A-Z0-9-]{5,}", flags=re.IGNORECASE)
_ACCESSORY_RE = re.compile(
    r"(記憶體散熱器|記憶體散熱|記憶體風扇|RAM\s*COOLER|MEMORY\s*COOLER|RAM\s*FAN|MEMORY\s*FAN)",
    flags=re.IGNORECASE,
)
_TRAILING_TAG_RE = re.compile(r"\bAI\b\s*$", flags=re.IGNORECASE)
_PLUS_SPLIT_RE = re.compile(r"[+＋]")
_SINGLE_RE = re.compile(r"(單條|單支|單顆)", flags=re.IGNORECASE)
_NB_RE = re.compile(r"(?<![A-Za-z0-9])NB(?![A-Za-z0-9])|筆電", flags=re.IGNORECASE)
_FIRST_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")
_BUNDLE_KEYWORDS_RE = re.compile(r"(大全配|優惠組合|組合|套餐|搭機|整機)", flags=re.IGNORECASE)
_NON_RAM_PART_RE = re.compile(
    r"(主機板|CPU|處理器|顯卡|SSD|硬碟|HDD|電源|機殼|散熱|水冷|風扇|電源供應器)",
    flags=re.IGNORECASE,
)
_MAKER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:\bBIWIN\b|佰維)", flags=re.IGNORECASE), "BIWIN"),
    (re.compile(r"(?:\bCORSAIR\b|海盜船)", flags=re.IGNORECASE), "CORSAIR"),
    (re.compile(r"(?:\bACER\b)", flags=re.IGNORECASE), "ACER"),
    (re.compile(r"(?:\bKINGSTON\b|金士頓)", flags=re.IGNORECASE), "KINGSTON"),
    (re.compile(r"(?:\bG\.?SKILL\b|芝奇)", flags=re.IGNORECASE), "G.SKILL"),
    (re.compile(r"(?:\bADATA\b|威剛)", flags=re.IGNORECASE), "ADATA"),
    (re.compile(r"(?:\bTEAMGROUP\b|\bTEAM\b|十銓)", flags=re.IGNORECASE), "TEAMGROUP"),
    (re.compile(r"(?:\bCRUCIAL\b|\bMICRON\b|美光)", flags=re.IGNORECASE), "MICRON"),
    (re.compile(r"(?:\bORIGIN\s*CODE\b)", flags=re.IGNORECASE), "ORIGIN CODE"),
    (re.compile(r"(?:\bAPACER\b|宇瞻)", flags=re.IGNORECASE), "APACER"),
    (re.compile(r"(?:\bKLEVV\b|科賦)", flags=re.IGNORECASE), "KLEVV"),
    (re.compile(r"(?:\bUMAX\b|宏泰|優美)", flags=re.IGNORECASE), "UMAX"),
]


def infer_ram_bundle(head: str) -> bool:
    candidate = head or ""
    if not candidate:
        return False
    if _BUNDLE_KEYWORDS_RE.search(candidate):
        return True
    if _PLUS_SPLIT_RE.search(candidate) and _NON_RAM_PART_RE.search(candidate):
        return True
    return False


def infer_ram_accessory(text: str) -> bool:
    return bool(_ACCESSORY_RE.search(text or ""))


def infer_ram_single_hint(text: str) -> bool:
    return bool(_SINGLE_RE.search(text or ""))


def infer_ram_notebook_hint(text: str, form_factor_hint: str | None) -> bool:
    return bool(_NB_RE.search(text or "")) or form_factor_hint == "SO-DIMM"


def _looks_like_part_number(token: str) -> bool:
    if not token or not _SKU_TOKEN_RE.fullmatch(token):
        return False
    alpha = sum(1 for ch in token if ch.isalpha())
    digit = sum(1 for ch in token if ch.isdigit())
    if alpha < 2 or digit < 2:
        return False
    if any(ch in token for ch in ("*", "×")):
        return False
    return True


def _extract_bracket_sku(text: str) -> str | None:
    for match in _BRACKET_CONTENT_RE.finditer(text or ""):
        content = match.group("content") or ""
        for raw in re.split(r"[\s,;/|]+", content):
            token = raw.strip().strip("()[]{}")
            if _looks_like_part_number(token):
                return token
    return None


def extract_ram_sku_hint(text: str) -> str:
    return _extract_bracket_sku(text) or clean_ram_fallback_title(text)


def infer_ram_maker(text: str) -> str | None:
    for pattern, normalized in _MAKER_PATTERNS:
        if pattern.search(text or ""):
            return normalized
    match = _FIRST_TOKEN_RE.search(text or "")
    if not match:
        return None
    token = match.group(0)
    if not any(ch.isalpha() for ch in token):
        return None
    return token.upper()


def clean_ram_fallback_title(title: str) -> str:
    line = normalize_spaces(strip_leading_note(first_line(title)))
    base = _BRACKET_REMOVE_RE.sub(" ", line)
    base = normalize_spaces(base)
    base = re.sub(r"([A-Za-z])(\d)", r"\1 \2", base)
    base = re.sub(r"(\d)([A-Za-z])", r"\1 \2", base)
    if base:
        base = _PLUS_SPLIT_RE.split(base, 1)[0].strip()
    base = _TRAILING_TAG_RE.sub("", base).strip()
    return base or line
