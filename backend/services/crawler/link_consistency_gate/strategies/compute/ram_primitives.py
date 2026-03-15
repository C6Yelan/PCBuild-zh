from __future__ import annotations

import re

from ...types import ListingInput, PageSignals
from ..shared_primitives import compose_page_text, normalize_upper_pattern_text, tokenize_model_tokens

_RE_BRACKETS = re.compile(r"[][(){}<>【】（）]", flags=re.UNICODE)
_RE_SEP_PHRASE = re.compile(r"[\\/._|,:;+=~-]+", flags=re.UNICODE)
_RE_SEP_TOKENS = re.compile(r"[\\/._|,:;+=~]+", flags=re.UNICODE)  # keep '-'

_RE_DDR = re.compile(r"(?<![A-Z0-9])DDR\s*([345])(?![A-Z0-9])", flags=re.UNICODE)
_RE_D_ABBR = re.compile(r"(?<![A-Z0-9])D([345])(?![A-Z0-9])", flags=re.UNICODE)
_RE_CAP_GB = re.compile(r"(?<![A-Z0-9])(\d{1,3})\s*(?:GB|G)(?![A-Z0-9])", flags=re.UNICODE)
_RE_CL = re.compile(r"(?<![A-Z0-9])CL\s*(\d{1,3})(?![A-Z0-9])", flags=re.UNICODE)
_RE_NUM_4_5 = re.compile(r"(?<![A-Z0-9])(\d{4,5})(?![A-Z0-9])", flags=re.UNICODE)

_RE_SPEC_LIKE = re.compile(r"^(?:DDR[345]|D[345])(?:L)?(?:-\d{3,5})?$", flags=re.UNICODE)
_RE_CJK_HEAD = re.compile(r"^[\u4e00-\u9fff]{2,8}", flags=re.UNICODE)
_RE_CJK_TOKEN = re.compile(r"[\u4e00-\u9fff]{2,8}", flags=re.UNICODE)

_NOISE_MARKERS = (
    "~組裝價~",
    "組裝價",
    "[組裝價]",
    "[組裝/升級]",
)

_SERIES_TOKENS = {
    "FURY",
    "BEAST",
    "DOMINATOR",
    "VENGEANCE",
    "RIPJAWS",
    "TRIDENT",
    "BALLISTIX",
    "LANCER",
}


def normalize_ram_phrase(text: str) -> str:
    return normalize_upper_pattern_text(
        text,
        prepare=strip_ram_noise,
        bracket_re=_RE_BRACKETS,
        separator_re=_RE_SEP_PHRASE,
    )


def normalize_ram_token_text(text: str) -> str:
    return normalize_upper_pattern_text(
        text,
        prepare=strip_ram_noise,
        bracket_re=_RE_BRACKETS,
        separator_re=_RE_SEP_TOKENS,
    )


def build_ram_page_text(signals: PageSignals) -> str:
    return compose_page_text(signals.page_title, signals.page_h1, signals.text_hint)


def build_ram_tokens(text: str) -> list[str]:
    tokens = set(tokenize_model_tokens(text, normalize=normalize_ram_token_text, min_length=2))
    phrase = normalize_ram_phrase(text)
    for match in _RE_DDR.finditer(phrase):
        tokens.add(f"DDR{match.group(1)}")
    for match in _RE_D_ABBR.finditer(phrase):
        tokens.add(f"DDR{match.group(1)}")
    for match in _RE_CAP_GB.finditer(phrase):
        tokens.add(f"{match.group(1)}GB")
    for match in _RE_CL.finditer(phrase):
        tokens.add(f"CL{match.group(1)}")
    for match in _RE_NUM_4_5.finditer(phrase):
        tokens.add(match.group(1))
    for token in _RE_CJK_TOKEN.findall(phrase):
        if token:
            tokens.add(token)
    return sorted(tokens)


def build_ram_listing_tokens(listing: ListingInput) -> list[str]:
    return build_ram_tokens(
        " ".join(
            [
                listing.sku_hint or "",
                listing.title or "",
                str(listing.extra.get("maker_hint") or ""),
                str(listing.extra.get("ddr_gen_hint") or ""),
                str(listing.extra.get("speed_mts_hint") or ""),
                str(listing.extra.get("capacity_gb_hint") or ""),
                str(listing.extra.get("kit_dimms_hint") or ""),
                str(listing.extra.get("cl_hint") or ""),
            ]
        )
    )


def extract_ram_identity_tokens(listing: ListingInput, listing_tokens: list[str]) -> set[str]:
    out: set[str] = {token for token in listing_tokens if is_ram_sku_token(token)}

    cjk_maker = ram_cjk_head_token(listing.sku_hint) or ram_cjk_head_token(listing.title)
    if cjk_maker:
        out.add(cjk_maker)

    maker = listing.extra.get("maker_hint")
    if isinstance(maker, str) and maker.strip():
        maker_norm = normalize_ram_phrase(maker)
        for token in maker_norm.split(" "):
            if token and len(token) >= 3 and token.isalpha():
                out.add(token)

    for token in listing_tokens:
        if token in _SERIES_TOKENS:
            out.add(token)

    return out


def extract_ram_spec_tokens(tokens: list[str]) -> set[str]:
    out: set[str] = set()
    for token in tokens:
        if not token:
            continue
        if token in {"DDR3", "DDR4", "DDR5"}:
            out.add(token)
            continue
        if token.startswith("CL") and token[2:].isdigit():
            out.add(token)
            continue
        if token.endswith("GB") and token[:-2].isdigit():
            out.add(token)
            continue
        if token.isdigit() and 4 <= len(token) <= 5:
            out.add(token)
    return out


def pick_ram_model_phrase(listing: ListingInput) -> tuple[str, str]:
    if is_ram_sku_like(listing.sku_hint):
        return listing.sku_hint, "sku_hint(sku)"

    parts: list[str] = []
    cjk_maker = ram_cjk_head_token(listing.sku_hint) or ram_cjk_head_token(listing.title)
    if cjk_maker:
        parts.append(cjk_maker)
    else:
        maker = listing.extra.get("maker_hint")
        if isinstance(maker, str) and maker.strip():
            parts.append(maker.strip())

    title_tokens = set(build_ram_tokens(listing.title))
    for token in sorted(title_tokens):
        if token in _SERIES_TOKENS:
            parts.append(token)
            break

    ddr = listing.extra.get("ddr_gen_hint")
    if isinstance(ddr, str) and ddr.strip():
        parts.append(ddr.strip())

    speed = listing.extra.get("speed_mts_hint")
    if isinstance(speed, int) and speed > 0:
        parts.append(str(speed))

    capacity = listing.extra.get("capacity_gb_hint")
    if isinstance(capacity, int) and capacity > 0:
        parts.append(f"{capacity}GB")

    cl = listing.extra.get("cl_hint")
    if isinstance(cl, int) and cl > 0:
        parts.append(f"CL{cl}")

    composed = " ".join(parts).strip()
    if composed:
        return composed, "composed"
    if (listing.sku_hint or "").strip():
        return listing.sku_hint, "sku_hint"
    return listing.title, "title"


def strip_ram_noise(text: str) -> str:
    out = text or ""
    for marker in _NOISE_MARKERS:
        out = out.replace(marker, " ")
    return out


def ram_cjk_head_token(text: str) -> str | None:
    normalized = (text or "").replace("\u3000", " ").replace("\xa0", " ")
    normalized = strip_ram_noise(normalized).lstrip()
    match = _RE_CJK_HEAD.match(normalized)
    if not match:
        return None
    token = match.group(0)
    if not token:
        return None
    return token


def is_ram_sku_token(token: str) -> bool:
    if not token or len(token) < 5:
        return False
    if _RE_SPEC_LIKE.fullmatch(token) is not None:
        return False
    if token.startswith("DDR") and token[3:].isdigit():
        return False
    if token.startswith("CL") and token[2:].isdigit():
        return False
    if token.endswith("GB") and token[:-2].isdigit():
        return False
    has_alpha = any("A" <= ch <= "Z" for ch in token)
    has_digit = any("0" <= ch <= "9" for ch in token)
    return has_alpha and has_digit


def is_ram_sku_like(sku_hint: str) -> bool:
    raw = (sku_hint or "").strip()
    if not raw:
        return False
    compact = raw.upper().replace(" ", "")
    if re.fullmatch(r"[A-Z0-9-]{5,}", compact, flags=re.UNICODE) is None:
        return False
    return is_ram_sku_token(compact)
