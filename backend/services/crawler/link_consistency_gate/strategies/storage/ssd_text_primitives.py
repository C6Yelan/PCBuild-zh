from __future__ import annotations

import re

from ..shared_primitives import normalize_upper_pattern_text, tokenize_model_tokens

_RE_BRACKETS = re.compile(r"[][(){}<>【】（）]", flags=re.UNICODE)
_RE_SEP_PHRASE = re.compile(r"[\\/._|,:;+=~-]+", flags=re.UNICODE)
_RE_SEP_TOKENS = re.compile(r"[\\/._|,:;+=~]+", flags=re.UNICODE)
_RE_CAPACITY = re.compile(r"(?<![A-Z0-9])(\d{1,4})\s*(TB|GB|T|G)(?![A-Z0-9])", flags=re.UNICODE)
_RE_CAPACITY_TOKEN = re.compile(r"^(\d{1,4})(TB|GB|T|G)$", flags=re.UNICODE)
_RE_SPEED_M = re.compile(r"^\d{3,5}M$", flags=re.UNICODE)
_RE_M2 = re.compile(r"M\s*\.?\s*2", flags=re.UNICODE)
_RE_25 = re.compile(r"2\s*\.?\s*5", flags=re.UNICODE)
_RE_PCIE = re.compile(r"PCI\s*E", flags=re.UNICODE)
_NOISE_MARKERS = ("~組裝價~", "組裝價", "[組裝價]", "[組裝/升級]")
_PROTO_TOKENS = {"SATA", "NVME", "AHCI", "PCIE"}


def normalize_ssd_phrase(text: str) -> str:
    return normalize_upper_pattern_text(
        text,
        prepare=strip_ssd_noise,
        bracket_re=_RE_BRACKETS,
        separator_re=_RE_SEP_PHRASE,
        replacements_after=((_RE_PCIE, "PCIE"),),
    )


def normalize_ssd_token_text(text: str) -> str:
    return normalize_upper_pattern_text(
        text,
        prepare=strip_ssd_noise,
        bracket_re=_RE_BRACKETS,
        separator_re=_RE_SEP_TOKENS,
        replacements_after=((_RE_PCIE, "PCIE"),),
    )


def build_ssd_tokens(text: str) -> list[str]:
    tokens = set(tokenize_model_tokens(text, normalize=normalize_ssd_token_text, min_length=2))
    phrase = normalize_ssd_phrase(text)
    tokens |= extract_ssd_capacity_tokens(phrase)
    for proto in _PROTO_TOKENS:
        rx = re.compile(rf"(?<![A-Z0-9]){re.escape(proto)}(?![A-Z0-9])", flags=re.UNICODE)
        if rx.search(phrase):
            tokens.add(proto)
    upper_text = (text or "").upper()
    if _RE_M2.search(upper_text):
        tokens.add("M2")
    if _RE_25.search(upper_text):
        tokens.add("2.5")
    return sorted(tokens)


def strip_ssd_noise(text: str) -> str:
    out = text or ""
    for marker in _NOISE_MARKERS:
        out = out.replace(marker, " ")
    return out


def canonical_ssd_capacity(amount: str, unit: str) -> str:
    unit = unit.upper()
    if unit == "T":
        unit = "TB"
    elif unit == "G":
        unit = "GB"
    return f"{int(amount)}{unit}"


def extract_ssd_capacity_tokens(text: str) -> set[str]:
    phrase = normalize_ssd_phrase(text)
    out: set[str] = set()
    for match in _RE_CAPACITY.finditer(phrase):
        out.add(canonical_ssd_capacity(match.group(1), match.group(2)))
    return out


def has_ssd_mixed_alnum(token: str) -> bool:
    has_alpha = any("A" <= ch <= "Z" for ch in token)
    has_digit = any("0" <= ch <= "9" for ch in token)
    return has_alpha and has_digit


def is_ssd_identity_token(token: str) -> bool:
    if not token or len(token) < 4:
        return False
    if not has_ssd_mixed_alnum(token):
        return False
    return not is_ssd_spec_like_token(token)


def is_ssd_spec_like_token(token: str) -> bool:
    if not token:
        return False
    if token.isdigit() or token in _PROTO_TOKENS:
        return True
    if token.startswith("GEN") and token[3:].isdigit():
        return True
    if token.startswith("PCIE") or token in {"M2", "2.5"}:
        return True
    if _RE_SPEED_M.fullmatch(token) is not None:
        return True
    if _RE_CAPACITY_TOKEN.fullmatch(token) is not None:
        return True
    return token in extract_ssd_capacity_tokens(token)


def is_ssd_sku_like(sku_hint: str) -> bool:
    if not (sku_hint or "").strip():
        return False
    phrase = normalize_ssd_phrase(sku_hint)
    token_candidates = tokenize_model_tokens(sku_hint, normalize=normalize_ssd_token_text, min_length=2)
    if not token_candidates or len(token_candidates) > 3:
        return False
    if not any(is_ssd_identity_token(token) for token in token_candidates):
        return False
    if all(is_ssd_spec_like_token(token) for token in token_candidates):
        return False
    return len(phrase) <= 48
