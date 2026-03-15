from __future__ import annotations

import re
from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from ..shared_primitives import (
    compose_page_text,
    model_phrase_found_decision,
    model_token_match_decision,
    model_token_missing_decision,
    normalize_spaces,
    normalize_upper_pattern_text,
    page_text_empty_decision,
    token_overlap_inconclusive_decision,
    token_weak_or_empty_decision,
)

_RE_SEP = re.compile(r"[\\/._|,:;+=~\-]+", flags=re.UNICODE)
_RE_BRACKET_SYMBOLS = re.compile(r"[\[\]【】\(\)（）\{\}<>]", flags=re.UNICODE)
_RE_TITLE_PREFIX = re.compile(r"^\s*[【\[]?(?:限搭|搭機價|組裝價|組裝/升級|促銷)[】\]]?\s*", flags=re.UNICODE)
_RE_TITLE_SPLIT = re.compile(r"[／/]", flags=re.UNICODE)
_RE_ALPHA_TO_DIGIT = re.compile(r"(?<=[A-Z])(?=[0-9])", flags=re.UNICODE)
_RE_DIGIT_TO_ALPHA = re.compile(r"(?<=[0-9])(?=[A-Z])", flags=re.UNICODE)
_RE_GEFORCE_GLUE = re.compile(r"GEFORCE(?=RTX|GTX)", flags=re.UNICODE)
_RE_RADEON_GLUE = re.compile(r"RADEON(?=RX)", flags=re.UNICODE)
_RE_ARC_GLUE = re.compile(r"ARC(?=[AB][0-9]{2,3})", flags=re.UNICODE)
_RE_NUM_SUFFIX_GLUE = re.compile(r"([0-9]{3,4})(TI|SUPER|XTX|XT)\b", flags=re.UNICODE)
_RE_TI_SUPER_GLUE = re.compile(r"TI(?=SUPER)", flags=re.UNICODE)
_RE_TOKEN = re.compile(r"[A-Z0-9]{2,}", flags=re.UNICODE)

_RE_ID_NVIDIA = re.compile(
    r"(?<![A-Z0-9])(?:GEFORCE\s*)?(RTX|GTX)\s*([0-9]{3,4})(?:\s*(TI))?(?:\s*(SUPER))?(?![A-Z0-9])",
    flags=re.UNICODE,
)
_RE_ID_NVIDIA_GT = re.compile(
    r"(?<![A-Z0-9])GT(?!X)\s*([0-9]{3,4})(?![A-Z0-9])",
    flags=re.UNICODE,
)
_RE_ID_NVIDIA_NSKU = re.compile(
    r"(?<![A-Z0-9])N\s*([0-9]{3,4})(?![A-Z0-9])",
    flags=re.UNICODE,
)
_RE_ID_AMD = re.compile(
    r"(?<![A-Z0-9])(?:RADEON\s*)?RX\s*([0-9]{3,4})(?:\s*(XTX|XT))?(?![A-Z0-9])",
    flags=re.UNICODE,
)
_RE_ID_AMD_R_SERIES = re.compile(
    r"(?<![A-Z0-9])(?:RADEON\s*)?R\s*([579])\s*([0-9]{3})(?![A-Z0-9])",
    flags=re.UNICODE,
)
_RE_ID_AMD_SKU_R_SERIES = re.compile(
    r"(?<![A-Z0-9])[A-Z]{1,4}R\s*([579])\s*([0-9]{3})(?![A-Z0-9])",
    flags=re.UNICODE,
)
_RE_ID_AMD_AI_PRO = re.compile(
    r"(?<![A-Z0-9])(?:RADEON\s*)?(?:AI\s*PRO\s*)?R\s*([0-9]{4})(?![A-Z0-9])",
    flags=re.UNICODE,
)
_RE_ID_INTEL = re.compile(
    r"(?<![A-Z0-9])ARC\s*([AB])\s*([0-9]{2,3})(?![A-Z0-9])",
    flags=re.UNICODE,
)


def _normalize_spaces(s: str) -> str:
    return normalize_spaces(s)


def _normalize_text(s: str) -> str:
    return normalize_upper_pattern_text(
        s,
        bracket_re=_RE_BRACKET_SYMBOLS,
        separator_re=_RE_SEP,
        replacements_before=(
            (_RE_GEFORCE_GLUE, "GEFORCE "),
            (_RE_RADEON_GLUE, "RADEON "),
            (_RE_ARC_GLUE, "ARC "),
            (_RE_NUM_SUFFIX_GLUE, r"\1 \2"),
            (_RE_TI_SUPER_GLUE, "TI "),
        ),
        replacements_after=(
            (_RE_ALPHA_TO_DIGIT, " "),
            (_RE_DIGIT_TO_ALPHA, " "),
        ),
    )


def _title_head(title: str) -> str:
    line = (title or "").splitlines()[0].strip() if title else ""
    if not line:
        return ""
    line = _RE_TITLE_PREFIX.sub("", line)
    line = _normalize_spaces(line)
    if not line:
        return ""
    return _RE_TITLE_SPLIT.split(line, maxsplit=1)[0].strip()


def _pick_model_phrase(listing: ListingInput) -> tuple[str, str]:
    model_hint = listing.extra.get("model_hint")
    if isinstance(model_hint, str) and model_hint.strip():
        return model_hint.strip(), "extra.model_hint"

    if (listing.sku_hint or "").strip():
        return listing.sku_hint.strip(), "sku_hint"

    return _title_head(listing.title), "title_head"


def _extract_gpu_identities(text: str) -> list[str]:
    norm = _normalize_text(text)
    out: set[str] = set()

    for m in _RE_ID_NVIDIA.finditer(norm):
        vendor = m.group(1)
        number = m.group(2)
        ti = m.group(3)
        sup = m.group(4)
        parts = [vendor, number]
        if ti:
            parts.append("TI")
        if sup:
            parts.append("SUPER")
        out.add("".join(parts))

    for m in _RE_ID_NVIDIA_GT.finditer(norm):
        out.add(f"GT{m.group(1)}")

    for m in _RE_ID_NVIDIA_NSKU.finditer(norm):
        # Legacy vendor SKU like N210/N710/N730 maps to GT legacy naming.
        out.add(f"GT{m.group(1)}")

    for m in _RE_ID_AMD.finditer(norm):
        number = m.group(1)
        suffix = m.group(2)
        parts = ["RX", number]
        if suffix:
            parts.append(suffix)
        out.add("".join(parts))

    for m in _RE_ID_AMD_R_SERIES.finditer(norm):
        out.add(f"R{m.group(1)}{m.group(2)}")

    for m in _RE_ID_AMD_SKU_R_SERIES.finditer(norm):
        out.add(f"R{m.group(1)}{m.group(2)}")

    for m in _RE_ID_AMD_AI_PRO.finditer(norm):
        out.add(f"R{m.group(1)}")

    for m in _RE_ID_INTEL.finditer(norm):
        letter = m.group(1)
        number = m.group(2)
        out.add(f"ARC{letter}{number}")

    return sorted(out)


def _extract_tokens(text: str) -> list[str]:
    norm = _normalize_text(text)
    return sorted(set(_RE_TOKEN.findall(norm)))


def _build_listing_tokens(model_phrase: str, listing_identities: list[str]) -> list[str]:
    out: set[str] = set(_extract_tokens(model_phrase))
    model_norm = _normalize_text(model_phrase)
    if model_norm:
        out.add(model_norm)
    for identity in listing_identities:
        out.add(identity)
        out.update(identity.split())
    return sorted(out)


def _build_page_tokens(page_text: str, page_identities: list[str]) -> list[str]:
    out: set[str] = set(_extract_tokens(page_text))
    for identity in page_identities:
        out.add(identity)
        out.update(identity.split())
    return sorted(out)


@dataclass(frozen=True)
class GpuStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        model_phrase_raw, model_source = _pick_model_phrase(listing)
        model_phrase_norm = _normalize_text(model_phrase_raw)

        page_text = compose_page_text(
            signals.text_hint,
            signals.page_title,
            signals.page_h1,
            signals.canonical_url,
            normalize=normalize_spaces,
        )
        page_text_norm = _normalize_text(page_text)

        listing_identities = _extract_gpu_identities(
            " ".join(
                [
                    model_phrase_raw,
                    listing.sku_hint or "",
                    str(listing.extra.get("model_hint") or ""),
                ]
            )
        )
        page_identities = _extract_gpu_identities(page_text)

        listing_tokens = _build_listing_tokens(model_phrase_raw, listing_identities)
        page_tokens = _build_page_tokens(page_text, page_identities)
        matched_tokens = sorted(set(listing_tokens) & set(page_tokens))

        if not page_text_norm:
            return page_text_empty_decision(
                listing_tokens=listing_tokens,
                notes=[f"model_source={model_source}", "page text empty"],
            )

        if not page_tokens and not page_identities:
            return token_weak_or_empty_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"model_source={model_source}", "page tokens too weak"],
            )

        listing_identity_set = set(listing_identities)
        page_identity_set = set(page_identities)
        matched_identity = sorted(listing_identity_set & page_identity_set)

        if model_phrase_norm and model_phrase_norm in page_text_norm:
            if listing_identity_set and page_identity_set and not matched_identity:
                # Avoid prefix false positives such as RTX 4060 vs RTX 4060 TI.
                pass
            else:
                phrase_matches = sorted(set(matched_tokens) | {model_phrase_norm} | set(matched_identity))
                return model_phrase_found_decision(
                    listing_tokens=listing_tokens,
                    page_tokens=page_tokens,
                    matched_tokens=phrase_matches,
                    notes=[f"model_source={model_source}", "phrase hit"],
                )

        if matched_identity:
            return model_token_match_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_identity,
                notes=[f"model_source={model_source}", "identity token match"],
            )

        if listing_identity_set and page_identity_set and not matched_identity:
            return model_token_missing_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[
                    f"model_source={model_source}",
                    f"identity mismatch: listing={sorted(listing_identity_set)[:2]} page={sorted(page_identity_set)[:2]}",
                ],
            )

        if not listing_identity_set or not page_identity_set:
            return token_weak_or_empty_decision(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"model_source={model_source}", "identity tokens weak or empty"],
            )

        return token_overlap_inconclusive_decision(
            listing_tokens=listing_tokens,
            page_tokens=page_tokens,
            matched_tokens=matched_tokens,
            notes=[f"model_source={model_source}", "token overlap inconclusive"],
        )
