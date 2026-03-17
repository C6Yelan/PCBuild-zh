# backend/services/crawler/link_consistency_gate/strategies/io_expansion/expansion_card_primitives.py
from __future__ import annotations

import re

from ...types import ListingInput, PageSignals
from ..shared_primitives import compose_page_text, normalize_pattern_text, normalize_spaces

_RE_SEP_PHRASE = re.compile(r"[\\/._|,:;+=~\-]+", flags=re.UNICODE)
_RE_SEP_TOKEN = re.compile(r"[\\/._|,:;+=~]+", flags=re.UNICODE)
_RE_BRACKET_SYMBOLS = re.compile(r"[\[\]【】\(\)（）\{\}<>]", flags=re.UNICODE)
_RE_COMPACT_KEEP = re.compile(r"[^A-Z0-9\u4e00-\u9fff]+", flags=re.UNICODE)
_RE_NON_ALNUM = re.compile(r"[^A-Z0-9]+", flags=re.UNICODE)
_RE_TOKEN = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*", flags=re.UNICODE)
_RE_TITLE_SLASH = re.compile(r"[／/]", flags=re.UNICODE)
_RE_M2 = re.compile(r"M[\s\.\-]*2", flags=re.UNICODE)


def normalize_expansion_card_phrase(text: str) -> str:
    return normalize_pattern_text(
        text,
        transform="upper",
        bracket_re=_RE_BRACKET_SYMBOLS,
        separator_re=_RE_SEP_PHRASE,
        replacements_before=((_RE_M2, "M2"),),
    )


def normalize_expansion_card_token_text(text: str) -> str:
    return normalize_pattern_text(
        text,
        transform="upper",
        bracket_re=_RE_BRACKET_SYMBOLS,
        separator_re=_RE_SEP_TOKEN,
        replacements_before=((_RE_M2, "M2"),),
    )


def compact_expansion_card_phrase(text: str) -> str:
    return _RE_COMPACT_KEEP.sub("", normalize_expansion_card_phrase(text))


def build_expansion_card_title_head(title: str) -> str:
    line = (title or "").splitlines()[0].strip() if title else ""
    if not line:
        return ""
    return _RE_TITLE_SLASH.split(line, maxsplit=1)[0].strip()


def pick_expansion_card_model_phrase(listing: ListingInput) -> tuple[str, str, bool]:
    model_hint = listing.extra.get("model_hint")
    if isinstance(model_hint, str) and model_hint.strip():
        return model_hint.strip(), "model_hint", True

    sku_hint = (listing.sku_hint or "").strip()
    if sku_hint:
        return sku_hint, "sku_hint", True

    return build_expansion_card_title_head(listing.title), "title_head", False


def build_expansion_card_phrase_candidates(text: str) -> list[str]:
    phrase = normalize_spaces(text)
    if not phrase:
        return []

    ordered: list[str] = []
    seen: set[str] = set()

    def add(candidate: str) -> None:
        normalized = normalize_expansion_card_phrase(candidate)
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        ordered.append(normalized)

    add(phrase)

    tokens = phrase.split()
    if len(tokens) >= 2:
        first = tokens[0]
        if not any(ch.isdigit() for ch in first):
            add(" ".join(tokens[1:]))

    return ordered


def is_expansion_card_pure_model_code_phrase(phrase: str) -> bool:
    normalized = normalize_expansion_card_phrase(phrase)
    if not normalized or " " in normalized:
        return False

    canonical = _RE_NON_ALNUM.sub("", normalized)
    if not canonical:
        return False

    has_alpha = any("A" <= ch <= "Z" for ch in canonical)
    has_digit = any("0" <= ch <= "9" for ch in canonical)
    return has_alpha and has_digit


def build_expansion_card_tokens(text: str) -> list[str]:
    normalized = normalize_expansion_card_token_text(text)
    base_tokens: list[str] = []
    tokens: set[str] = set()

    for match in _RE_TOKEN.finditer(normalized):
        token = match.group(0).strip("-")
        if not token:
            continue
        base_tokens.append(token)
        tokens.add(token)

        if "-" in token:
            split_parts: list[str] = []
            for part in token.split("-"):
                part = part.strip("-")
                if not part:
                    continue
                split_parts.append(part)
                tokens.add(part)
            if split_parts:
                tokens.add("".join(split_parts))

    for idx in range(len(base_tokens) - 1):
        if base_tokens[idx] == "GEN" and base_tokens[idx + 1].isdigit():
            tokens.add(f"GEN{base_tokens[idx + 1]}")
        if base_tokens[idx] == "THUNDERBOLTEX" and base_tokens[idx + 1].isdigit():
            tokens.add(f"THUNDERBOLTEX{base_tokens[idx + 1]}")

    return sorted(tokens)


def is_expansion_card_identity_token(token: str) -> bool:
    normalized = (token or "").strip("-")
    if not normalized:
        return False

    canonical = normalized.replace("-", "")
    if len(canonical) < 4:
        return False

    has_alpha = any("A" <= ch <= "Z" for ch in canonical)
    has_digit = any("0" <= ch <= "9" for ch in canonical)
    return has_alpha and has_digit


def extract_expansion_card_identity_tokens(tokens: list[str]) -> set[str]:
    return {token for token in tokens if is_expansion_card_identity_token(token)}


def build_expansion_card_page_text(signals: PageSignals) -> str:
    return compose_page_text(signals.text_hint, normalize=normalize_spaces)


def build_expansion_card_title_head_candidates(
    listing: ListingInput,
    *,
    model_phrase: str,
    model_source: str,
    has_model: bool,
) -> tuple[list[str], bool]:
    if not has_model or model_source not in {"model_hint", "sku_hint"}:
        return [], False

    title_head = build_expansion_card_title_head(listing.title)
    if not title_head:
        return [], False
    if normalize_expansion_card_phrase(title_head) == normalize_expansion_card_phrase(model_phrase):
        return [], False

    candidates = build_expansion_card_phrase_candidates(title_head)
    return candidates, bool(candidates)
