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
_RE_NON_ALNUM = re.compile(r"[^A-Z0-9]+", flags=re.UNICODE)
_RE_TOKEN = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*", flags=re.UNICODE)
_RE_TITLE_TRUNC = re.compile(r"[\(（【\[]", flags=re.UNICODE)
_RE_TITLE_SLASH = re.compile(r"[／/]", flags=re.UNICODE)
_RE_ASCII_START = re.compile(r"[A-Z0-9]", flags=re.UNICODE)
_RE_HAS_CJK = re.compile(r"[\u4e00-\u9fff]", flags=re.UNICODE)
_RE_ONLY_CJK_SEP_PREFIX = re.compile(r"^[\u4e00-\u9fff\s\-_/]+$", flags=re.UNICODE)
_RE_WEAK_POWER = re.compile(r"^[0-9]{2,4}W$", flags=re.UNICODE)

_STOPWORDS = {
    "ATX",
    "SFX",
    "SFXL",
    "TFX",
    "EPS",
    "PCIE",
    "PCI",
    "GEN",
    "GEN5",
    "MODULAR",
    "FULL",
    "SEMI",
    "NON",
    "FAN",
    "SILENT",
    "BLACK",
    "WHITE",
    "GOLD",
    "BRONZE",
    "PLATINUM",
    "TITANIUM",
    "POWER",
    "SUPPLY",
    "PSU",
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


def _is_weak_model_phrase(s: str) -> bool:
    # SKU weak check for wattage-only hints, tolerant to casing/spaces/trailing separators.
    canonical = _RE_NON_ALNUM.sub("", _normalize_spaces(s).upper())
    if not canonical:
        return True
    return _RE_WEAK_POWER.fullmatch(canonical) is not None


def _title_ascii_tail(title_head: str) -> str:
    segment = _normalize_spaces(title_head)
    if not segment:
        return ""
    if _RE_HAS_CJK.search(segment) is None:
        return ""

    match = _RE_ASCII_START.search(segment.upper())
    if match is None:
        return ""

    idx = match.start()
    prefix = segment[:idx]
    if idx > 0 and _RE_ONLY_CJK_SEP_PREFIX.fullmatch(prefix) is not None:
        return segment[idx:].strip()
    return ""


def _pick_model_phrase(listing: ListingInput) -> tuple[str, str, bool]:
    model_hint = listing.extra.get("model_hint")
    if isinstance(model_hint, str) and model_hint.strip():
        return model_hint.strip(), "extra.model_hint", False

    sku = (listing.sku_hint or "").strip()
    if sku:
        if not _is_weak_model_phrase(sku):
            return sku, "sku_hint", False
        title_head = _title_head(listing.title)
        title_ascii_tail = _title_ascii_tail(title_head)
        if title_ascii_tail:
            return title_ascii_tail, "title_ascii_tail", True
        return title_head, "title_head", True

    return _title_head(listing.title), "title_first_line", False


def _prefer_alnum_subphrase(raw: str) -> str:
    text = _normalize_spaces(raw)
    if not text:
        return ""

    match = _RE_ASCII_START.search(text.upper())
    if match is None:
        return text

    idx = match.start()
    prefix = text[:idx]
    if idx > 0 and _RE_HAS_CJK.search(prefix) and _RE_ONLY_CJK_SEP_PREFIX.fullmatch(prefix) is not None:
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
            for part in tok.split("-"):
                part = part.strip("-")
                if part:
                    out.add(part)

    return sorted(out)


def _is_identity_token(tok: str) -> bool:
    t = (tok or "").strip("-")
    if not t or t in _STOPWORDS:
        return False

    has_alpha = any("A" <= ch <= "Z" for ch in t)
    has_digit = any("0" <= ch <= "9" for ch in t)
    if has_digit:
        return True
    return has_alpha and len(t) >= 5


def _is_weak_token(tok: str) -> bool:
    t = (tok or "").strip("-")
    if _RE_WEAK_POWER.fullmatch(t) is not None:
        return True
    return t in {"80PLUS", "BRONZE", "GOLD", "PLATINUM", "TITANIUM"}


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
class PsuStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        raw_phrase, model_source, ignored_weak_sku_hint = _pick_model_phrase(listing)
        candidates = _build_model_candidates(raw_phrase)
        base_notes = [f"model_source={model_source}"]
        if ignored_weak_sku_hint:
            base_notes.append("ignored_weak_sku_hint")

        listing_tokens = _tokenize(" ".join(candidates))

        page_text = _build_page_text(signals)
        if not _normalize_for_phrase(page_text):
            evidence = _evidence(
                listing_tokens=listing_tokens,
                page_tokens=[],
                matched_tokens=[],
                notes=[*base_notes, "page_text_empty"],
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
                notes=[*base_notes, "page_tokens_too_weak"],
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
                    notes=[*base_notes, f"candidate_used={cand}", "phrase_match"],
                )
                return MatchDecision(
                    status="match",
                    score=None,
                    reason_code="MODEL_PHRASE_FOUND",
                    evidence=evidence,
                )

        listing_identity = _extract_identity_tokens(listing_tokens)
        if not listing_identity:
            evidence = _evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=[],
                notes=[*base_notes, "listing_identity_empty"],
            )
            return MatchDecision(
                status="mismatch",
                score=None,
                reason_code="MODEL_TOKEN_MISSING",
                evidence=evidence,
            )

        matched_tokens = sorted(listing_identity & set(page_tokens))
        if not matched_tokens:
            evidence = _evidence(
                listing_tokens=sorted(listing_identity),
                page_tokens=page_tokens,
                matched_tokens=[],
                notes=[*base_notes, "identity_overlap_empty"],
            )
            return MatchDecision(
                status="mismatch",
                score=None,
                reason_code="IDENTITY_TOKEN_MISSING",
                evidence=evidence,
            )

        if all(_is_weak_token(tok) for tok in matched_tokens):
            evidence = _evidence(
                listing_tokens=sorted(listing_identity),
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[*base_notes, "only_weak_identity_overlap"],
            )
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="TOKEN_OVERLAP_INCONCLUSIVE",
                evidence=evidence,
            )

        evidence = _evidence(
            listing_tokens=sorted(listing_identity),
            page_tokens=page_tokens,
            matched_tokens=matched_tokens,
            notes=[*base_notes, "fallback_token_match"],
        )
        return MatchDecision(
            status="match",
            score=None,
            reason_code="MODEL_TOKEN_MATCH",
            evidence=evidence,
        )
