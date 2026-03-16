from __future__ import annotations

import re

from ...types import ListingInput, PageSignals

_RE_WS = re.compile(r"\s+", flags=re.UNICODE)
_RE_TOKEN = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*", flags=re.UNICODE)
_RE_ALPHA_WORD = re.compile(r"[A-Z]{2,}", flags=re.UNICODE)

_TITLE_PREFIXES = (
    "[組裝價]",
    "[組裝/升級]",
)

_BRAND_TOKENS = {"AMD", "INTEL"}
_CONTEXT_STOPWORDS = {
    "AMD",
    "INTEL",
    "CPU",
    "PROCESSOR",
    "MPK",
    "BOX",
    "TRAY",
}


def normalize_cpu_text(text: str) -> str:
    normalized = (text or "").replace("\u3000", " ").replace("\xa0", " ")
    normalized = normalized.upper()
    return _RE_WS.sub(" ", normalized).strip()


def strip_cpu_title_prefix(title: str) -> str:
    normalized = (title or "").lstrip()
    for prefix in _TITLE_PREFIXES:
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :].lstrip()
    return normalized


def pick_cpu_identifier(listing: ListingInput) -> tuple[str, str]:
    extra_model_hint = listing.extra.get("model_hint")
    if isinstance(extra_model_hint, str) and extra_model_hint.strip():
        return extra_model_hint, "extra.model_hint"

    if (listing.sku_hint or "").strip():
        return listing.sku_hint, "sku_hint"

    return listing.title, "title"


def build_cpu_model_phrase(identifier: str) -> str:
    parts = [part for part in (identifier or "").split(" ") if part and part not in _BRAND_TOKENS]
    return normalize_cpu_text(" ".join(parts))


def build_cpu_page_text(signals: PageSignals) -> str:
    parts: list[str] = []
    for part in (signals.page_title, signals.page_h1, signals.text_hint):
        if part:
            parts.append(part)
    return normalize_cpu_text(" ".join(parts))


def cpu_model_phrase_in_page(page_text: str, phrase: str) -> bool:
    if not page_text or not phrase:
        return False
    pattern = re.compile(rf"(?<![A-Z0-9]){re.escape(phrase)}(?![A-Z0-9])", flags=re.UNICODE)
    return pattern.search(page_text) is not None


def build_cpu_model_tokens(text: str) -> list[str]:
    normalized = normalize_cpu_text(text)
    tokens: set[str] = set()
    for match in _RE_TOKEN.finditer(normalized):
        token = match.group(0).strip("-")
        if not token or not any(ch.isdigit() for ch in token):
            continue
        tokens.add(token)
        if "-" not in token:
            continue
        for part in token.split("-"):
            part = part.strip("-")
            if not part:
                continue
            if any(ch.isdigit() for ch in part) and len(part) >= 3:
                tokens.add(part)
    return sorted(tokens)


def extract_cpu_context_words(text: str) -> set[str]:
    normalized = normalize_cpu_text(text)
    words: set[str] = set()
    for match in _RE_ALPHA_WORD.finditer(normalized):
        word = match.group(0)
        if word in _CONTEXT_STOPWORDS:
            continue
        words.add(word)
    return words


def is_cpu_strong_alnum_token(token: str) -> bool:
    if not token or len(token) < 4:
        return False
    has_alpha = any("A" <= ch <= "Z" for ch in token)
    has_digit = any("0" <= ch <= "9" for ch in token)
    return has_alpha and has_digit
