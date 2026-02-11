from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..types import ListingInput, MatchDecision, PageSignals


_RE_WS = re.compile(r"\s+", flags=re.UNICODE)
_RE_KEEP_ALNUM = re.compile(r"[^A-Z0-9]+", flags=re.UNICODE)
_RE_TOKEN = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*", flags=re.UNICODE)
_RE_PAREN = re.compile(r"\(([^)]{1,80})\)", flags=re.UNICODE)


def _normalize_spaces(s: str) -> str:
    s = (s or "").replace("\u3000", " ").replace("\xa0", " ")
    s = _RE_WS.sub(" ", s).strip()
    return s


def _canonical_alnum(s: str) -> str:
    s = _normalize_spaces(s).upper()
    s = _RE_KEEP_ALNUM.sub("", s)
    return s


def _build_page_text(signals: PageSignals) -> str:
    parts: list[str] = []
    for s in (signals.page_title, signals.page_h1, signals.text_hint):
        if s:
            parts.append(s)
    return _normalize_spaces(" ".join(parts))


def _extract_tokens(s: str) -> list[str]:
    text = _normalize_spaces(s).upper()
    out: set[str] = set()
    for m in _RE_TOKEN.finditer(text):
        tok = m.group(0).strip("-")
        if not tok:
            continue
        out.add(tok)
        if "-" in tok:
            for part in tok.split("-"):
                part = part.strip("-")
                if part:
                    out.add(part)
    return sorted(out)


def _is_identity_token(tok: str) -> bool:
    raw = (tok or "").replace("-", "")
    if len(raw) < 5:
        return False
    has_alpha = any("A" <= ch <= "Z" for ch in raw)
    has_digit = any("0" <= ch <= "9" for ch in raw)
    return has_alpha and has_digit


def _title_model_fallback(title: str) -> str:
    first_line = (title or "").splitlines()[0].strip() if title else ""
    if not first_line:
        return ""

    for m in _RE_PAREN.finditer(first_line):
        chunk = _normalize_spaces(m.group(1))
        if not chunk:
            continue
        for tok in _extract_tokens(chunk):
            if _is_identity_token(tok):
                return tok

    for tok in _extract_tokens(first_line):
        if _is_identity_token(tok):
            return tok

    return first_line


def _pick_model_candidate(listing: ListingInput) -> tuple[str, str]:
    model_hint = listing.extra.get("model_hint")
    if isinstance(model_hint, str) and model_hint.strip():
        return model_hint.strip(), "extra.model_hint"

    if (listing.sku_hint or "").strip():
        return listing.sku_hint.strip(), "sku_hint"

    return _title_model_fallback(listing.title), "title_fallback"


def _build_listing_tokens(listing: ListingInput, model_candidate: str) -> list[str]:
    listing_text = " ".join(
        [
            model_candidate or "",
            listing.sku_hint or "",
            listing.title or "",
            str(listing.extra.get("model_hint") or ""),
        ]
    )
    return _extract_tokens(listing_text)


def _make_evidence(
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
class HddStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        model_candidate, model_src = _pick_model_candidate(listing)
        canonical_model_key = _canonical_alnum(model_candidate)

        page_text = _build_page_text(signals)
        canonical_page_text = _canonical_alnum(page_text)

        listing_tokens = _build_listing_tokens(listing, model_candidate)

        if not page_text or not canonical_page_text:
            evidence = _make_evidence(
                listing_tokens=listing_tokens,
                page_tokens=[],
                matched_tokens=[],
                notes=[f"model_source={model_src}", "page_text is empty after normalization"],
            )
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="PAGE_TEXT_EMPTY",
                evidence=evidence,
            )

        page_tokens = _extract_tokens(page_text)
        matched_tokens = sorted(set(listing_tokens) & set(page_tokens))

        if not canonical_model_key:
            evidence = _make_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"model_source={model_src}", "canonical model key is empty"],
            )
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="MODEL_EMPTY",
                evidence=evidence,
            )

        if canonical_model_key in canonical_page_text:
            evidence = _make_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[f"model_source={model_src}", "canonical model phrase found in page text"],
            )
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_PHRASE_FOUND",
                evidence=evidence,
            )

        listing_identity = {t for t in listing_tokens if _is_identity_token(t)}
        page_identity = {t for t in page_tokens if _is_identity_token(t)}
        matched_identity = sorted(listing_identity & page_identity)

        if matched_identity:
            evidence = _make_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[
                    f"model_source={model_src}",
                    f"identity token overlap found: {matched_identity[0]}",
                ],
            )
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_TOKEN_MATCH",
                evidence=evidence,
            )

        if listing_identity:
            evidence = _make_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[
                    f"model_source={model_src}",
                    "listing has identity token(s) but page has no identity overlap",
                ],
            )
            return MatchDecision(
                status="mismatch",
                score=None,
                reason_code="IDENTITY_TOKEN_MISSING",
                evidence=evidence,
            )

        evidence = _make_evidence(
            listing_tokens=listing_tokens,
            page_tokens=page_tokens,
            matched_tokens=matched_tokens,
            notes=[
                f"model_source={model_src}",
                "token overlap is inconclusive for HDD",
            ],
        )
        return MatchDecision(
            status="uncertain",
            score=None,
            reason_code="TOKEN_OVERLAP_INCONCLUSIVE",
            evidence=evidence,
        )

