from __future__ import annotations

import re
from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from ..shared_primitives import build_evidence, compose_page_text, normalize_pattern_text

_RE_BRACKETS = re.compile(r"[][(){}<>【】（）]", flags=re.UNICODE)
_RE_SEP_PHRASE = re.compile(r"[\\/._|,:;+=~-]+", flags=re.UNICODE)
_RE_SEP_TOKENS = re.compile(r"[\\/._|,:;+=~]+", flags=re.UNICODE)  # keep '-' for SKU tokens

_RE_TOKEN = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*", flags=re.UNICODE)

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

# Keep this list intentionally small; treat these as "identity-ish" even without a full SKU.
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


def _strip_noise(s: str) -> str:
    out = s or ""
    for w in _NOISE_MARKERS:
        out = out.replace(w, " ")
    return out


def _cjk_head_token(s: str) -> str | None:
    s = (s or "").replace("\u3000", " ").replace("\xa0", " ")
    s = _strip_noise(s).lstrip()
    m = _RE_CJK_HEAD.match(s)
    if not m:
        return None
    tok = m.group(0)
    if not tok:
        return None
    return tok


def _normalize_for_phrase(s: str) -> str:
    # Phrase match should be separator-tolerant (including '-' vs whitespace).
    return normalize_pattern_text(
        s,
        transform="upper",
        prepare=_strip_noise,
        bracket_re=_RE_BRACKETS,
        separator_re=_RE_SEP_PHRASE,
    )


def _normalize_for_tokens(s: str) -> str:
    # Tokenization keeps '-' so SKU tokens (e.g., F5-6000J... / AX5U...-...) survive.
    return normalize_pattern_text(
        s,
        transform="upper",
        prepare=_strip_noise,
        bracket_re=_RE_BRACKETS,
        separator_re=_RE_SEP_TOKENS,
    )


def _extract_tokens(text: str) -> list[str]:
    """
    Extract a stable token set for RAM matching.
    - identity candidates: SKU-like tokens (keeps '-'), brand/series words, mixed alnum tokens
    - spec helpers: DDR{3/4/5}, speed(4~5 digits), {N}GB, CL{N}
    """
    tokens: set[str] = set()

    raw = _normalize_for_tokens(text)
    for m in _RE_TOKEN.finditer(raw):
        tok = m.group(0)
        if len(tok) < 2:
            continue
        tokens.add(tok)
        if "-" in tok:
            for part in tok.split("-"):
                if len(part) >= 2:
                    tokens.add(part)

    # Add canonical spec tokens from a more separator-tolerant normalization.
    phrase = _normalize_for_phrase(text)
    for m in _RE_DDR.finditer(phrase):
        tokens.add(f"DDR{m.group(1)}")
    for m in _RE_D_ABBR.finditer(phrase):
        tokens.add(f"DDR{m.group(1)}")
    for m in _RE_CAP_GB.finditer(phrase):
        tokens.add(f"{m.group(1)}GB")
    for m in _RE_CL.finditer(phrase):
        tokens.add(f"CL{m.group(1)}")
    for m in _RE_NUM_4_5.finditer(phrase):
        tokens.add(m.group(1))

    for t in _RE_CJK_TOKEN.findall(phrase):
        if t:
            tokens.add(t)

    return sorted(tokens)


def _is_sku_token(tok: str) -> bool:
    if not tok or len(tok) < 5:
        return False
    if _RE_SPEC_LIKE.fullmatch(tok) is not None:
        return False
    if tok.startswith("DDR") and tok[3:].isdigit():
        return False
    if tok.startswith("CL") and tok[2:].isdigit():
        return False
    if tok.endswith("GB") and tok[:-2].isdigit():
        return False
    has_alpha = any("A" <= ch <= "Z" for ch in tok)
    has_digit = any("0" <= ch <= "9" for ch in tok)
    return has_alpha and has_digit


def _is_sku_like(sku_hint: str) -> bool:
    raw = (sku_hint or "").strip()
    if not raw:
        return False
    compact = raw.upper().replace(" ", "")
    if re.fullmatch(r"[A-Z0-9-]{5,}", compact, flags=re.UNICODE) is None:
        return False
    return _is_sku_token(compact)


def _pick_model_phrase(listing: ListingInput) -> tuple[str, str]:
    if _is_sku_like(listing.sku_hint):
        return listing.sku_hint, "sku_hint(sku)"

    parts: list[str] = []
    cjk_mk = _cjk_head_token(listing.sku_hint) or _cjk_head_token(listing.title)
    if cjk_mk:
        parts.append(cjk_mk)
    else:
        mk = listing.extra.get("maker_hint")
        if isinstance(mk, str) and mk.strip():
            parts.append(mk.strip())

    # A tiny series allowlist helps when maker is present but the page omits it.
    title_tokens = set(_extract_tokens(listing.title))
    for t in sorted(title_tokens):
        if t in _SERIES_TOKENS:
            parts.append(t)
            break

    ddr = listing.extra.get("ddr_gen_hint")
    if isinstance(ddr, str) and ddr.strip():
        parts.append(ddr.strip())

    speed = listing.extra.get("speed_mts_hint")
    if isinstance(speed, int) and speed > 0:
        parts.append(str(speed))

    cap = listing.extra.get("capacity_gb_hint")
    if isinstance(cap, int) and cap > 0:
        parts.append(f"{cap}GB")

    cl = listing.extra.get("cl_hint")
    if isinstance(cl, int) and cl > 0:
        parts.append(f"CL{cl}")

    composed = " ".join(parts).strip()
    if composed:
        return composed, "composed"

    # Last resort: sku_hint/title, but keep it short by using normalization later.
    if (listing.sku_hint or "").strip():
        return listing.sku_hint, "sku_hint"
    return listing.title, "title"


def _extract_identity_tokens(listing: ListingInput, listing_tokens: list[str]) -> set[str]:
    out: set[str] = {t for t in listing_tokens if _is_sku_token(t)}

    cjk_mk = _cjk_head_token(listing.sku_hint) or _cjk_head_token(listing.title)
    if cjk_mk:
        out.add(cjk_mk)

    mk = listing.extra.get("maker_hint")
    if isinstance(mk, str) and mk.strip():
        mk_norm = _normalize_for_phrase(mk)
        for t in mk_norm.split(" "):
            if t and len(t) >= 3 and t.isalpha():
                out.add(t)

    for t in listing_tokens:
        if t in _SERIES_TOKENS:
            out.add(t)

    return out


def _extract_spec_tokens(tokens: list[str]) -> set[str]:
    out: set[str] = set()
    for t in tokens:
        if not t:
            continue
        if t in {"DDR3", "DDR4", "DDR5"}:
            out.add(t)
            continue
        if t.startswith("CL") and t[2:].isdigit():
            out.add(t)
            continue
        if t.endswith("GB") and t[:-2].isdigit():
            out.add(t)
            continue
        if t.isdigit() and 4 <= len(t) <= 5:
            out.add(t)
            continue
    return out


@dataclass(frozen=True)
class RamStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        page_text_raw = compose_page_text(signals.page_title, signals.page_h1, signals.text_hint)
        page_text_norm = _normalize_for_phrase(page_text_raw)

        # Evidence must always contain stable keys with list[str] values.
        listing_tokens = _extract_tokens(
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

        if not page_text_norm:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=[],
                matched_tokens=[],
                notes=["page_text is empty (page_title/page_h1/text_hint all missing or blank)"],
            )
            return MatchDecision(status="uncertain", score=None, reason_code="PAGE_TEXT_EMPTY", evidence=evidence)

        page_tokens = _extract_tokens(page_text_raw)
        matched_tokens = sorted(set(listing_tokens) & set(page_tokens))

        model_phrase_raw, model_src = _pick_model_phrase(listing)
        model_phrase_norm = _normalize_for_phrase(model_phrase_raw)

        if not model_phrase_norm:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=["model_phrase is empty after normalization (no usable identifier)"],
            )
            return MatchDecision(status="uncertain", score=None, reason_code="MODEL_EMPTY", evidence=evidence)

        if model_phrase_norm in page_text_norm:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"phrase_hit via normalized substring (model_source={model_src})"],
            )
            return MatchDecision(status="match", score=None, reason_code="MODEL_PHRASE_FOUND", evidence=evidence)

        listing_identity = _extract_identity_tokens(listing, listing_tokens)
        listing_spec = _extract_spec_tokens(listing_tokens)

        page_set = set(page_tokens)
        matched_identity = sorted(listing_identity & page_set)
        matched_spec = sorted(listing_spec & page_set)

        if matched_identity and matched_spec:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[
                    "token_match: identity+spec tokens overlapped",
                    f"matched_identity={matched_identity[:2]}, matched_spec={matched_spec[:2]}",
                ],
            )
            return MatchDecision(status="match", score=None, reason_code="MODEL_TOKEN_MATCH", evidence=evidence)

        if listing_identity and not matched_identity:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[
                    "mismatch: no identity token matched",
                    f"identity_tokens(listing)={len(listing_identity)}",
                ],
            )
            return MatchDecision(status="mismatch", score=None, reason_code="IDENTITY_TOKEN_MISSING", evidence=evidence)

        evidence = build_evidence(
            listing_tokens=listing_tokens,
            page_tokens=page_tokens,
            matched_tokens=matched_tokens,
            notes=[
                "uncertain: token overlap insufficient (need >=1 identity + >=1 spec token)",
                f"identity/spec(listing)={len(listing_identity)}/{len(listing_spec)}",
            ],
        )
        return MatchDecision(status="uncertain", score=None, reason_code="TOKEN_OVERLAP_INCONCLUSIVE", evidence=evidence)
