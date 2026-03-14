# backend/services/crawler/link_consistency_gate/strategies/ssd.py
from __future__ import annotations

import re
from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from ..shared_primitives import build_evidence, compose_page_text, normalize_pattern_text, normalize_spaces


_RE_BRACKETS = re.compile(r"[][(){}<>【】（）]", flags=re.UNICODE)
_RE_SEP_PHRASE = re.compile(r"[\\/._|,:;+=~-]+", flags=re.UNICODE)
_RE_SEP_TOKENS = re.compile(r"[\\/._|,:;+=~]+", flags=re.UNICODE)  # keep '-'
_RE_TOKEN = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*", flags=re.UNICODE)

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


def _strip_noise(s: str) -> str:
    out = s or ""
    for w in _NOISE_MARKERS:
        out = out.replace(w, " ")
    return out


def _normalize_for_phrase(s: str) -> str:
    return normalize_pattern_text(
        s,
        transform="upper",
        prepare=_strip_noise,
        bracket_re=_RE_BRACKETS,
        separator_re=_RE_SEP_PHRASE,
        replacements_after=((_RE_PCIE, "PCIE"),),
    )


def _normalize_for_tokens(s: str) -> str:
    return normalize_pattern_text(
        s,
        transform="upper",
        prepare=_strip_noise,
        bracket_re=_RE_BRACKETS,
        separator_re=_RE_SEP_TOKENS,
        replacements_after=((_RE_PCIE, "PCIE"),),
    )


def _first_title_segment(title: str) -> str:
    first_line = (title or "").splitlines()[0] if title else ""
    first_line = first_line.strip()
    if not first_line:
        return ""
    segment = re.split(r"[／/]", first_line, maxsplit=1)[0]
    return segment.strip()


def _build_page_text(signals: PageSignals) -> str:
    return compose_page_text(signals.page_title, signals.page_h1, signals.text_hint)


def _canonical_capacity(amount: str, unit: str) -> str:
    unit = unit.upper()
    if unit == "T":
        unit = "TB"
    elif unit == "G":
        unit = "GB"
    return f"{int(amount)}{unit}"


def _capacity_tokens(text: str) -> set[str]:
    phrase = _normalize_for_phrase(text)
    out: set[str] = set()
    for m in _RE_CAPACITY.finditer(phrase):
        out.add(_canonical_capacity(m.group(1), m.group(2)))
    return out


def _has_mixed_alnum(tok: str) -> bool:
    has_alpha = any("A" <= ch <= "Z" for ch in tok)
    has_digit = any("0" <= ch <= "9" for ch in tok)
    return has_alpha and has_digit


def _is_spec_like_token(tok: str) -> bool:
    if not tok:
        return False
    if tok.isdigit():
        return True
    if tok in _PROTO_TOKENS:
        return True
    if tok.startswith("GEN") and tok[3:].isdigit():
        return True
    if tok.startswith("PCIE"):
        return True
    if tok in {"M2", "2.5"}:
        return True
    if _RE_SPEED_M.fullmatch(tok) is not None:
        return True
    if _RE_CAPACITY_TOKEN.fullmatch(tok) is not None:
        return True
    if tok in _capacity_tokens(tok):
        return True
    return False


def _is_identity_token(tok: str) -> bool:
    if not tok or len(tok) < 4:
        return False
    if not _has_mixed_alnum(tok):
        return False
    if _is_spec_like_token(tok):
        return False
    return True


def _extract_tokens(text: str) -> list[str]:
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

    phrase = _normalize_for_phrase(text)
    tokens |= _capacity_tokens(phrase)

    for p in _PROTO_TOKENS:
        rx = re.compile(rf"(?<![A-Z0-9]){re.escape(p)}(?![A-Z0-9])", flags=re.UNICODE)
        if rx.search(phrase):
            tokens.add(p)

    if _RE_M2.search((text or "").upper()):
        tokens.add("M2")
    if _RE_25.search((text or "").upper()):
        tokens.add("2.5")

    return sorted(tokens)


def _extract_identity_tokens(tokens: list[str]) -> set[str]:
    return {t for t in tokens if _is_identity_token(t)}


def _extract_spec_tokens(tokens: list[str]) -> set[str]:
    out: set[str] = set()
    for t in tokens:
        if not t:
            continue
        if t in _PROTO_TOKENS or t in {"M2", "2.5"}:
            out.add(t)
            continue
        if _RE_CAPACITY_TOKEN.fullmatch(t) is not None:
            m = _RE_CAPACITY_TOKEN.fullmatch(t)
            if m:
                out.add(_canonical_capacity(m.group(1), m.group(2)))
            continue
        if t in _capacity_tokens(t):
            out.add(t)
            continue
    return out


def _is_sku_like(sku_hint: str) -> bool:
    if not (sku_hint or "").strip():
        return False
    phrase = _normalize_for_phrase(sku_hint)
    token_candidates = _RE_TOKEN.findall(_normalize_for_tokens(sku_hint))
    if not token_candidates:
        return False
    if len(token_candidates) > 3:
        return False
    if not any(_is_identity_token(t) for t in token_candidates):
        return False
    if all(_is_spec_like_token(t) for t in token_candidates):
        return False
    # Avoid treating long descriptive strings as SKU.
    return len(phrase) <= 48


def _hint_spec_tokens(listing: ListingInput) -> set[str]:
    out: set[str] = set()
    interface = listing.extra.get("interface_hint")
    protocol = listing.extra.get("protocol_hint")
    form_factor = listing.extra.get("form_factor_hint")

    for v in (interface, protocol):
        if not isinstance(v, str) or not v.strip():
            continue
        n = _normalize_for_phrase(v)
        if "SATA" in n:
            out.add("SATA")
        if "NVME" in n:
            out.add("NVME")
        if "AHCI" in n:
            out.add("AHCI")
        if "PCIE" in n:
            out.add("PCIE")

    if isinstance(form_factor, str) and form_factor.strip():
        n = _normalize_for_phrase(form_factor)
        if _RE_M2.search(n):
            out.add("M2")
        if _RE_25.search(n):
            out.add("2.5")

    return out


def _pick_model_phrase(listing: ListingInput) -> tuple[str, str]:
    if _is_sku_like(listing.sku_hint):
        return listing.sku_hint, "sku_hint(sku)"

    segment = _first_title_segment(listing.title)
    brand_hint = listing.extra.get("brand_hint")
    if isinstance(brand_hint, str) and brand_hint.strip():
        if segment:
            segment_norm = _normalize_for_phrase(segment)
            brand_norm = _normalize_for_phrase(brand_hint)
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


@dataclass(frozen=True)
class SsdStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        page_text_raw = _build_page_text(signals)
        page_text_norm = _normalize_for_phrase(page_text_raw)

        listing_tokens = _extract_tokens(
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
        listing_tokens = sorted(set(listing_tokens) | _hint_spec_tokens(listing))

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
                notes=[f"phrase match hit (model_source={model_src})"],
            )
            return MatchDecision(status="match", score=None, reason_code="MODEL_PHRASE_FOUND", evidence=evidence)

        listing_identity = _extract_identity_tokens(listing_tokens)
        listing_spec = _extract_spec_tokens(listing_tokens)
        page_identity = _extract_identity_tokens(page_tokens)
        page_spec = _extract_spec_tokens(page_tokens)

        matched_identity = sorted(listing_identity & page_identity)
        matched_spec = sorted(listing_spec & page_spec)

        if matched_identity and matched_spec:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[
                    "token match via identity+spec overlap",
                    f"matched_identity={matched_identity[:2]}, matched_spec={matched_spec[:2]}",
                ],
            )
            return MatchDecision(status="match", score=None, reason_code="MODEL_TOKEN_MATCH", evidence=evidence)

        if listing_identity and not matched_identity:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=["listing has identity tokens but page has no identity-token overlap"],
            )
            return MatchDecision(status="mismatch", score=None, reason_code="IDENTITY_TOKEN_MISSING", evidence=evidence)

        evidence = build_evidence(
            listing_tokens=listing_tokens,
            page_tokens=page_tokens,
            matched_tokens=matched_tokens,
            notes=["token overlap is inconclusive for SSD"],
        )
        return MatchDecision(status="uncertain", score=None, reason_code="TOKEN_OVERLAP_INCONCLUSIVE", evidence=evidence)
