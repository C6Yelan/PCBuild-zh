from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..types import ListingInput, MatchDecision, PageSignals


_RE_WS = re.compile(r"\s+", flags=re.UNICODE)
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
    s = (s or "").replace("\u3000", " ").replace("\xa0", " ")
    return _RE_WS.sub(" ", s).strip()


def _normalize_text(s: str) -> str:
    s = _normalize_spaces(s).upper()
    s = _RE_GEFORCE_GLUE.sub("GEFORCE ", s)
    s = _RE_RADEON_GLUE.sub("RADEON ", s)
    s = _RE_ARC_GLUE.sub("ARC ", s)
    s = _RE_NUM_SUFFIX_GLUE.sub(r"\1 \2", s)
    s = _RE_TI_SUPER_GLUE.sub("TI ", s)
    s = _RE_BRACKET_SYMBOLS.sub(" ", s)
    s = _RE_SEP.sub(" ", s)
    s = _RE_ALPHA_TO_DIGIT.sub(" ", s)
    s = _RE_DIGIT_TO_ALPHA.sub(" ", s)
    return _RE_WS.sub(" ", s).strip()


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


def _build_page_text(signals: PageSignals) -> str:
    parts: list[str] = []
    for s in (signals.text_hint, signals.page_title, signals.page_h1, signals.canonical_url):
        if s:
            parts.append(s)
    return _normalize_spaces(" ".join(parts))


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


def _evidence(
    listing_tokens: list[str],
    page_tokens: list[str],
    matched_tokens: list[str],
    notes: list[str],
) -> dict[str, Any]:
    return {
        "listing_tokens": list(listing_tokens),
        "page_tokens": list(page_tokens),
        "matched_tokens": list(matched_tokens),
        "notes": list(notes),
    }


@dataclass(frozen=True)
class GpuStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        model_phrase_raw, model_source = _pick_model_phrase(listing)
        model_phrase_norm = _normalize_text(model_phrase_raw)

        page_text = _build_page_text(signals)
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
            evidence = _evidence(
                listing_tokens=listing_tokens,
                page_tokens=[],
                matched_tokens=[],
                notes=[f"model_source={model_source}", "page text empty"],
            )
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="PAGE_TEXT_EMPTY",
                evidence=evidence,
            )

        if not page_tokens and not page_identities:
            evidence = _evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"model_source={model_source}", "page tokens too weak"],
            )
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="TOKEN_WEAK_OR_EMPTY",
                evidence=evidence,
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
                evidence = _evidence(
                    listing_tokens=listing_tokens,
                    page_tokens=page_tokens,
                    matched_tokens=phrase_matches,
                    notes=[f"model_source={model_source}", "phrase hit"],
                )
                return MatchDecision(
                    status="match",
                    score=None,
                    reason_code="MODEL_PHRASE_FOUND",
                    evidence=evidence,
                )

        if matched_identity:
            evidence = _evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_identity,
                notes=[f"model_source={model_source}", "identity token match"],
            )
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_TOKEN_MATCH",
                evidence=evidence,
            )

        if listing_identity_set and page_identity_set and not matched_identity:
            evidence = _evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[
                    f"model_source={model_source}",
                    f"identity mismatch: listing={sorted(listing_identity_set)[:2]} page={sorted(page_identity_set)[:2]}",
                ],
            )
            return MatchDecision(
                status="mismatch",
                score=None,
                reason_code="MODEL_TOKEN_MISSING",
                evidence=evidence,
            )

        if not listing_identity_set or not page_identity_set:
            evidence = _evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"model_source={model_source}", "identity tokens weak or empty"],
            )
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="TOKEN_WEAK_OR_EMPTY",
                evidence=evidence,
            )

        evidence = _evidence(
            listing_tokens=listing_tokens,
            page_tokens=page_tokens,
            matched_tokens=matched_tokens,
            notes=[f"model_source={model_source}", "token overlap inconclusive"],
        )
        return MatchDecision(
            status="uncertain",
            score=None,
            reason_code="TOKEN_OVERLAP_INCONCLUSIVE",
            evidence=evidence,
        )
