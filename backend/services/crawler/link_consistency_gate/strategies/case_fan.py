from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..types import ListingInput, MatchDecision, PageSignals


_RE_WS = re.compile(r"\s+", flags=re.UNICODE)
_RE_SEP_PHRASE = re.compile(r"[\\/._|,:;+=~\-]+", flags=re.UNICODE)
_RE_SEP_TOKEN = re.compile(r"[\\/._|,:;+=~]+", flags=re.UNICODE)  # keep '-'
_RE_BRACKET_SYMBOLS = re.compile(r"[\[\]【】\(\)（）\{\}<>]", flags=re.UNICODE)
_RE_CLEAN_COMPACT = re.compile(r"[^A-Z0-9\u4e00-\u9fff]+", flags=re.UNICODE)
_RE_TOKEN = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*", flags=re.UNICODE)
_RE_TITLE_TRUNC = re.compile(r"[\(（【\[]", flags=re.UNICODE)
_RE_TITLE_SLASH = re.compile(r"[／/]", flags=re.UNICODE)
_RE_ASCII_START = re.compile(r"[A-Z0-9]", flags=re.UNICODE)
_RE_HAS_CJK = re.compile(r"[\u4e00-\u9fff]", flags=re.UNICODE)
_RE_SIZE_TOKEN = re.compile(r"^(?:\d{2,4}|\d{1,3}(?:MM|CM)|\d{2,4}RPM)$", flags=re.UNICODE)

_IDENTITY_STOPWORDS = {
    "ARGB",
    "RGB",
    "LED",
    "PWM",
    "RPM",
    "MM",
    "CM",
    "CASE",
    "FAN",
    "USB",
    "TYPE",
    "TYPEC",
    "TYPE-C",
    "PACK",
    "PCS",
    "BLACK",
    "WHITE",
    "SILENT",
}


def _normalize_spaces(s: str) -> str:
    s = (s or "").replace("\u3000", " ").replace("\xa0", " ")
    return _RE_WS.sub(" ", s).strip()


def _normalize_for_phrase(s: str) -> str:
    s = _normalize_spaces(s).upper()
    s = _RE_BRACKET_SYMBOLS.sub(" ", s)
    s = _RE_SEP_PHRASE.sub(" ", s)
    return _RE_WS.sub(" ", s).strip()


def _normalize_for_token(s: str) -> str:
    s = _normalize_spaces(s).upper()
    s = _RE_BRACKET_SYMBOLS.sub(" ", s)
    s = _RE_SEP_TOKEN.sub(" ", s)
    return _RE_WS.sub(" ", s).strip()


def _compact(s: str) -> str:
    return _RE_CLEAN_COMPACT.sub("", _normalize_for_phrase(s))


def _title_head(title: str) -> str:
    line = (title or "").splitlines()[0].strip() if title else ""
    if not line:
        return ""
    line = _RE_TITLE_SLASH.split(line, maxsplit=1)[0].strip()
    m = _RE_TITLE_TRUNC.search(line)
    if m is not None:
        line = line[: m.start()]
    return _normalize_spaces(line)


def _pick_model_phrase(listing: ListingInput) -> tuple[str, str]:
    model_hint = listing.extra.get("model_hint")
    if isinstance(model_hint, str) and model_hint.strip():
        return model_hint.strip(), "extra.model_hint"

    if (listing.sku_hint or "").strip():
        return listing.sku_hint.strip(), "sku_hint"

    return _title_head(listing.title), "title_head"


def _prefer_alnum_subphrase(raw: str) -> str:
    text = _normalize_spaces(raw)
    if not text:
        return ""

    match = _RE_ASCII_START.search(text.upper())
    if match is None:
        return text

    idx = match.start()
    prefix = text[:idx]
    if idx > 0 and _RE_HAS_CJK.search(prefix) is not None and _RE_ASCII_START.search(prefix.upper()) is None:
        tail = text[idx:].strip()
        if tail:
            return tail
    return text


def _build_model_candidates(raw: str) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()

    def _add(s: str) -> None:
        norm = _normalize_for_phrase(s)
        if not norm or norm in seen:
            return
        seen.add(norm)
        ordered.append(norm)

    _add(raw)
    _add(_prefer_alnum_subphrase(raw))
    return ordered


def _build_page_text(signals: PageSignals) -> str:
    parts: list[str] = []
    for s in (signals.text_hint, signals.page_title, signals.page_h1):
        if s:
            parts.append(s)
    return _normalize_spaces(" ".join(parts))


def _tokenize(text: str) -> list[str]:
    norm = _normalize_for_token(text)
    out: set[str] = set()

    for m in _RE_TOKEN.finditer(norm):
        tok = m.group(0).strip("-")
        if not tok:
            continue
        out.add(tok)
        if "-" in tok:
            parts: list[str] = []
            for part in tok.split("-"):
                part = part.strip("-")
                if not part:
                    continue
                out.add(part)
                parts.append(part)
            if parts:
                out.add("".join(parts))

    return sorted(out)


def _is_size_token(tok: str) -> bool:
    t = (tok or "").replace("-", "")
    if not t:
        return True
    return _RE_SIZE_TOKEN.fullmatch(t) is not None


def _is_identity_token(tok: str) -> bool:
    t = (tok or "").strip("-")
    if not t:
        return False

    base = t.replace("-", "")
    if not base:
        return False
    if t in _IDENTITY_STOPWORDS or base in _IDENTITY_STOPWORDS:
        return False
    if _is_size_token(base):
        return False

    has_alpha = any("A" <= ch <= "Z" for ch in base)
    has_digit = any("0" <= ch <= "9" for ch in base)
    if has_alpha and has_digit:
        return True
    return has_alpha and len(base) >= 4


def _extract_identity_tokens(tokens: list[str]) -> set[str]:
    return {t for t in tokens if _is_identity_token(t)}


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
class CaseFanStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        raw_phrase, model_source = _pick_model_phrase(listing)
        candidates = _build_model_candidates(raw_phrase)
        listing_tokens = _tokenize(" ".join(candidates))

        page_text = _build_page_text(signals)
        if not _normalize_for_phrase(page_text):
            evidence = _evidence(
                listing_tokens=listing_tokens,
                page_tokens=[],
                matched_tokens=[],
                notes=[f"model_source={model_source}", "page_text_empty"],
            )
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="PAGE_TEXT_EMPTY",
                evidence=evidence,
            )

        page_tokens = _tokenize(page_text)
        if len(page_tokens) < 2:
            evidence = _evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=[],
                notes=[f"model_source={model_source}", "page_tokens_too_weak"],
            )
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="TOKEN_WEAK_OR_EMPTY",
                evidence=evidence,
            )

        page_compact = _compact(page_text)
        for cand in candidates:
            cand_compact = _compact(cand)
            if cand_compact and cand_compact in page_compact:
                evidence = _evidence(
                    listing_tokens=listing_tokens,
                    page_tokens=page_tokens,
                    matched_tokens=[cand],
                    notes=[f"model_source={model_source}", f"candidate_used={cand}", "phrase_match"],
                )
                return MatchDecision(
                    status="match",
                    score=None,
                    reason_code="MODEL_PHRASE_FOUND",
                    evidence=evidence,
                )

        listing_identity = _extract_identity_tokens(listing_tokens)
        page_identity = _extract_identity_tokens(page_tokens)
        overlap_tokens = sorted(set(listing_tokens) & set(page_tokens))
        matched_identity = sorted(listing_identity & page_identity)

        if not listing_identity or not page_identity:
            evidence = _evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=overlap_tokens,
                notes=[
                    f"model_source={model_source}",
                    f"identity tokens weak or empty(listing/page)={len(listing_identity)}/{len(page_identity)}",
                ],
            )
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="TOKEN_WEAK_OR_EMPTY",
                evidence=evidence,
            )

        if matched_identity:
            evidence = _evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=overlap_tokens,
                notes=[
                    f"model_source={model_source}",
                    "fallback_token_match",
                    f"strong_overlap={len(matched_identity)}",
                ],
            )
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_TOKEN_MATCH",
                evidence=evidence,
            )

        if not overlap_tokens:
            evidence = _evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=[],
                notes=[f"model_source={model_source}", "identity_overlap_empty"],
            )
            return MatchDecision(
                status="mismatch",
                score=None,
                reason_code="IDENTITY_TOKEN_MISSING",
                evidence=evidence,
            )

        evidence = _evidence(
            listing_tokens=listing_tokens,
            page_tokens=page_tokens,
            matched_tokens=overlap_tokens,
            notes=[f"model_source={model_source}", "only_weak_identity_overlap"],
        )
        return MatchDecision(
            status="uncertain",
            score=None,
            reason_code="TOKEN_OVERLAP_INCONCLUSIVE",
            evidence=evidence,
        )
