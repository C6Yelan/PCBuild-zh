from __future__ import annotations

import re

from ...types import ListingInput, PageSignals
from ..shared_primitives import compose_page_text, normalize_upper_pattern_text, tokenize_model_tokens

_RE_BRACKETS = re.compile(r"[][(){}<>【】（）]", flags=re.UNICODE)
_RE_SEP_PHRASE = re.compile(r"[\\/._|,:;+=~-]+", flags=re.UNICODE)
_RE_SEP_TOKENS = re.compile(r"[\\/._|,:;+=~]+", flags=re.UNICODE)  # keep '-'

_RE_CAPACITY = re.compile(r"(?<![A-Z0-9])(\d{1,4})\s*(TB|GB|T|G)(?![A-Z0-9])", flags=re.UNICODE)
_RE_CAPACITY_TOKEN = re.compile(r"^(\d{1,4})(TB|GB|T|G)$", flags=re.UNICODE)
_RE_SPEED_M = re.compile(r"^\d{3,5}M$", flags=re.UNICODE)
_RE_M2 = re.compile(r"M\s*\.?\s*2", flags=re.UNICODE)
_RE_25 = re.compile(r"2\s*\.?\s*5", flags=re.UNICODE)
_RE_PCIE = re.compile(r"PCI\s*E", flags=re.UNICODE)
_RE_CJK_CHAR = re.compile(r"[\u4e00-\u9fff]", flags=re.UNICODE)

_NOISE_MARKERS = (
    "~組裝價~",
    "組裝價",
    "[組裝價]",
    "[組裝/升級]",
)

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


def build_ssd_page_text(signals: PageSignals) -> str:
    return compose_page_text(signals.page_title, signals.page_h1, signals.text_hint)


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


def extract_ssd_identity_tokens(tokens: list[str]) -> set[str]:
    return {token for token in tokens if is_ssd_identity_token(token)}


def extract_ssd_spec_tokens(tokens: list[str]) -> set[str]:
    out: set[str] = set()
    for token in tokens:
        if not token:
            continue
        if token in _PROTO_TOKENS or token in {"M2", "2.5"}:
            out.add(token)
            continue
        if _RE_CAPACITY_TOKEN.fullmatch(token) is not None:
            match = _RE_CAPACITY_TOKEN.fullmatch(token)
            if match:
                out.add(canonical_ssd_capacity(match.group(1), match.group(2)))
            continue
        if token in extract_ssd_capacity_tokens(token):
            out.add(token)
    return out


def pick_ssd_model_phrase(listing: ListingInput) -> tuple[str, str]:
    if is_ssd_sku_like(listing.sku_hint):
        return listing.sku_hint, "sku_hint(sku)"

    segment = first_ssd_title_segment(listing.title)
    brand_hint = listing.extra.get("brand_hint")
    if isinstance(brand_hint, str) and brand_hint.strip():
        if segment:
            segment_norm = normalize_ssd_phrase(segment)
            brand_norm = normalize_ssd_phrase(brand_hint)
            if _RE_CJK_CHAR.search(segment):
                return segment, "title_segment(no_brand_for_cjk)"
            if brand_norm and brand_norm in segment_norm:
                return segment, "title_segment(brand_already_in_segment)"
            return f"{brand_hint.strip()} {segment}", "title_segment+brand_hint"
        return brand_hint.strip(), "brand_hint"

    if segment:
        return segment, "title_segment"
    if (listing.title or "").strip():
        return listing.title, "title"
    return listing.sku_hint, "sku_hint"


def build_ssd_listing_tokens(listing: ListingInput) -> list[str]:
    tokens = build_ssd_tokens(
        " ".join(
            [
                listing.sku_hint or "",
                listing.title or "",
                str(listing.extra.get("brand_hint") or ""),
                str(listing.extra.get("model_hint") or ""),
                str(listing.extra.get("interface_hint") or ""),
                str(listing.extra.get("protocol_hint") or ""),
                str(listing.extra.get("form_factor_hint") or ""),
            ]
        )
    )
    return sorted(set(tokens) | extract_ssd_hint_spec_tokens(listing))


def strip_ssd_noise(text: str) -> str:
    out = text or ""
    for marker in _NOISE_MARKERS:
        out = out.replace(marker, " ")
    return out


def first_ssd_title_segment(title: str) -> str:
    first_line = (title or "").splitlines()[0] if title else ""
    first_line = first_line.strip()
    if not first_line:
        return ""
    segment = re.split(r"[／/]", first_line, maxsplit=1)[0]
    return segment.strip()


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


def is_ssd_identity_token(token: str) -> bool:
    if not token or len(token) < 4:
        return False
    if not has_ssd_mixed_alnum(token):
        return False
    if is_ssd_spec_like_token(token):
        return False
    return True


def is_ssd_spec_like_token(token: str) -> bool:
    if not token:
        return False
    if token.isdigit():
        return True
    if token in _PROTO_TOKENS:
        return True
    if token.startswith("GEN") and token[3:].isdigit():
        return True
    if token.startswith("PCIE"):
        return True
    if token in {"M2", "2.5"}:
        return True
    if _RE_SPEED_M.fullmatch(token) is not None:
        return True
    if _RE_CAPACITY_TOKEN.fullmatch(token) is not None:
        return True
    if token in extract_ssd_capacity_tokens(token):
        return True
    return False


def is_ssd_sku_like(sku_hint: str) -> bool:
    if not (sku_hint or "").strip():
        return False
    phrase = normalize_ssd_phrase(sku_hint)
    token_candidates = tokenize_model_tokens(sku_hint, normalize=normalize_ssd_token_text, min_length=2)
    if not token_candidates:
        return False
    if len(token_candidates) > 3:
        return False
    if not any(is_ssd_identity_token(token) for token in token_candidates):
        return False
    if all(is_ssd_spec_like_token(token) for token in token_candidates):
        return False
    return len(phrase) <= 48


def extract_ssd_hint_spec_tokens(listing: ListingInput) -> set[str]:
    out: set[str] = set()
    interface = listing.extra.get("interface_hint")
    protocol = listing.extra.get("protocol_hint")
    form_factor = listing.extra.get("form_factor_hint")

    for value in (interface, protocol):
        if not isinstance(value, str) or not value.strip():
            continue
        normalized = normalize_ssd_phrase(value)
        if "SATA" in normalized:
            out.add("SATA")
        if "NVME" in normalized:
            out.add("NVME")
        if "AHCI" in normalized:
            out.add("AHCI")
        if "PCIE" in normalized:
            out.add("PCIE")

    if isinstance(form_factor, str) and form_factor.strip():
        normalized = normalize_ssd_phrase(form_factor)
        if _RE_M2.search(normalized):
            out.add("M2")
        if _RE_25.search(normalized):
            out.add("2.5")

    return out


def has_ssd_mixed_alnum(token: str) -> bool:
    has_alpha = any("A" <= ch <= "Z" for ch in token)
    has_digit = any("0" <= ch <= "9" for ch in token)
    return has_alpha and has_digit
