from __future__ import annotations

import re
from dataclasses import dataclass

from ...types import ListingInput, MatchDecision, PageSignals
from ..shared_primitives import build_evidence, compose_page_text, normalize_pattern_text, normalize_spaces


_RE_SEP_PHRASE = re.compile(r"[\\/._|,:;+=~\-]+", flags=re.UNICODE)
_RE_SEP_TOKEN = re.compile(r"[\\/._|,:;+=~]+", flags=re.UNICODE)  # keep '-'
_RE_BRACKET_SYMBOLS = re.compile(r"[\[\]【】\(\)（）\{\}<>]", flags=re.UNICODE)
_RE_COMPACT_KEEP = re.compile(r"[^A-Z0-9\u4e00-\u9fff]+", flags=re.UNICODE)
_RE_NON_ALNUM = re.compile(r"[^A-Z0-9]+", flags=re.UNICODE)
_RE_TOKEN = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*", flags=re.UNICODE)
_RE_TITLE_SLASH = re.compile(r"[／/]", flags=re.UNICODE)
_RE_M2 = re.compile(r"M[\s\.\-]*2", flags=re.UNICODE)

_WEAK_IDENTITY_TOKENS = {"GEN3", "GEN4", "GEN5", "USB4"}


def _normalize_spaces(s: str) -> str:
    return normalize_spaces(s)


def _normalize_for_phrase(s: str) -> str:
    return normalize_pattern_text(
        s,
        transform="upper",
        bracket_re=_RE_BRACKET_SYMBOLS,
        separator_re=_RE_SEP_PHRASE,
        replacements_before=((_RE_M2, "M2"),),
    )


def _normalize_for_token(s: str) -> str:
    return normalize_pattern_text(
        s,
        transform="upper",
        bracket_re=_RE_BRACKET_SYMBOLS,
        separator_re=_RE_SEP_TOKEN,
        replacements_before=((_RE_M2, "M2"),),
    )


def _compact(s: str) -> str:
    return _RE_COMPACT_KEEP.sub("", _normalize_for_phrase(s))


def _title_head(title: str) -> str:
    line = (title or "").splitlines()[0].strip() if title else ""
    if not line:
        return ""
    return _RE_TITLE_SLASH.split(line, maxsplit=1)[0].strip()


def _pick_model_phrase(listing: ListingInput) -> tuple[str, str, bool]:
    model_hint = listing.extra.get("model_hint")
    if isinstance(model_hint, str) and model_hint.strip():
        return model_hint.strip(), "model_hint", True

    sku_hint = (listing.sku_hint or "").strip()
    if sku_hint:
        return sku_hint, "sku_hint", True

    return _title_head(listing.title), "title_head", False


def _build_phrase_candidates(model_phrase: str) -> list[str]:
    phrase = _normalize_spaces(model_phrase)
    if not phrase:
        return []

    ordered: list[str] = []
    seen: set[str] = set()

    def _add(s: str) -> None:
        norm = _normalize_for_phrase(s)
        if not norm or norm in seen:
            return
        seen.add(norm)
        ordered.append(norm)

    _add(phrase)

    tokens = phrase.split()
    if len(tokens) >= 2:
        first = tokens[0]
        if not any(ch.isdigit() for ch in first):
            _add(" ".join(tokens[1:]))

    return ordered


def _is_pure_model_code_phrase(phrase: str) -> bool:
    norm = _normalize_for_phrase(phrase)
    if not norm:
        return False

    if " " in norm:
        return False

    canonical = _RE_NON_ALNUM.sub("", norm)
    if not canonical:
        return False

    has_alpha = any("A" <= ch <= "Z" for ch in canonical)
    has_digit = any("0" <= ch <= "9" for ch in canonical)
    return has_alpha and has_digit


def _tokenize(text: str) -> list[str]:
    norm = _normalize_for_token(text)
    base_tokens: list[str] = []
    out: set[str] = set()

    for m in _RE_TOKEN.finditer(norm):
        tok = m.group(0).strip("-")
        if not tok:
            continue
        base_tokens.append(tok)
        out.add(tok)

        if "-" in tok:
            split_parts: list[str] = []
            for part in tok.split("-"):
                part = part.strip("-")
                if not part:
                    continue
                split_parts.append(part)
                out.add(part)
            if split_parts:
                out.add("".join(split_parts))

    for i in range(len(base_tokens) - 1):
        if base_tokens[i] == "GEN" and base_tokens[i + 1].isdigit():
            out.add(f"GEN{base_tokens[i + 1]}")
        if base_tokens[i] == "THUNDERBOLTEX" and base_tokens[i + 1].isdigit():
            out.add(f"THUNDERBOLTEX{base_tokens[i + 1]}")

    return sorted(out)


def _is_identity_token(tok: str) -> bool:
    t = (tok or "").strip("-")
    if not t:
        return False

    canonical = t.replace("-", "")
    if len(canonical) < 4:
        return False

    has_alpha = any("A" <= ch <= "Z" for ch in canonical)
    has_digit = any("0" <= ch <= "9" for ch in canonical)
    return has_alpha and has_digit


def _extract_identity_tokens(tokens: list[str]) -> set[str]:
    return {tok for tok in tokens if _is_identity_token(tok)}


@dataclass(frozen=True)
class ExpansionCardStrategy:
    def decide(self, listing: ListingInput, signals: PageSignals) -> MatchDecision:
        model_phrase, model_source, has_model = _pick_model_phrase(listing)
        model_candidates = _build_phrase_candidates(model_phrase)
        title_head_candidates: list[str] = []
        base_notes = [f"model_source={model_source}"]

        if has_model and model_source in {"model_hint", "sku_hint"}:
            title_head = _title_head(listing.title)
            if title_head and _normalize_for_phrase(title_head) != _normalize_for_phrase(model_phrase):
                title_head_candidates = _build_phrase_candidates(title_head)
                if title_head_candidates:
                    base_notes.append("added_title_head_candidates")

        page_text = compose_page_text(signals.text_hint, normalize=normalize_spaces)
        listing_tokens = _tokenize(model_phrase)
        page_tokens = _tokenize(page_text)

        if not _normalize_spaces(page_text):
            evidence = build_evidence(
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

        compact_page = _compact(page_text)
        phrase_sources: list[tuple[str, str]] = [(cand, "model_phrase") for cand in model_candidates]
        phrase_sources.extend((cand, "title_head") for cand in title_head_candidates)

        for cand, phrase_source in phrase_sources:
            if _is_pure_model_code_phrase(cand):
                continue
            compact_cand = _compact(cand)
            if compact_cand and compact_cand in compact_page:
                match_notes = [*base_notes, f"candidate_used={cand}", "phrase_match"]
                if phrase_source == "title_head":
                    match_notes.append("phrase_source=title_head")
                evidence = build_evidence(
                    listing_tokens=_tokenize(cand),
                    page_tokens=page_tokens,
                    matched_tokens=[cand],
                    notes=match_notes,
                )
                return MatchDecision(
                    status="match",
                    score=None,
                    reason_code="MODEL_PHRASE_FOUND",
                    evidence=evidence,
                )

        listing_identity = _extract_identity_tokens(listing_tokens)
        page_identity = _extract_identity_tokens(page_tokens)
        matched_tokens = sorted(list(listing_identity & page_identity))

        if not listing_identity or not page_identity:
            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[*base_notes, "identity_tokens_weak_or_empty"],
            )
            return MatchDecision(
                status="uncertain",
                score=None,
                reason_code="TOKEN_WEAK_OR_EMPTY",
                evidence=evidence,
            )

        if matched_tokens:
            if all(tok in _WEAK_IDENTITY_TOKENS for tok in matched_tokens):
                evidence = build_evidence(
                    listing_tokens=listing_tokens,
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

            evidence = build_evidence(
                listing_tokens=listing_tokens,
                page_tokens=page_tokens,
                matched_tokens=matched_tokens,
                notes=[*base_notes, "token_fallback_match"],
            )
            return MatchDecision(
                status="match",
                score=None,
                reason_code="MODEL_TOKEN_MATCH",
                evidence=evidence,
            )

        evidence = build_evidence(
            listing_tokens=listing_tokens,
            page_tokens=page_tokens,
            matched_tokens=[],
            notes=[*base_notes, "no_identity_token_overlap"],
        )
        return MatchDecision(
            status="mismatch",
            score=None,
            reason_code="IDENTITY_TOKEN_MISSING",
            evidence=evidence,
        )
