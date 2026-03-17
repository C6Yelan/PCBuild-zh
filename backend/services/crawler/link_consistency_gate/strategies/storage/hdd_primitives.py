from __future__ import annotations

import re

from ...types import ListingInput, PageSignals
from ..shared_primitives import compose_page_text, normalize_spaces

_RE_WS = re.compile(r"\s+", flags=re.UNICODE)
_RE_KEEP_ALNUM = re.compile(r"[^A-Z0-9]+", flags=re.UNICODE)
_RE_TOKEN = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*", flags=re.UNICODE)
_RE_PAREN = re.compile(r"\(([^)]{1,80})\)", flags=re.UNICODE)


def normalize_hdd_spaces(text: str) -> str:
    return _RE_WS.sub(" ", (text or "").replace("\u3000", " ").replace("\xa0", " ")).strip()


def normalize_hdd_model_key(text: str) -> str:
    return _RE_KEEP_ALNUM.sub("", normalize_hdd_spaces(text).upper())


def build_hdd_page_text(signals: PageSignals) -> tuple[str, str]:
    page_text = compose_page_text(signals.page_title, signals.page_h1, signals.text_hint, normalize=normalize_spaces)
    return page_text, normalize_hdd_model_key(page_text)


def build_hdd_listing_tokens(listing: ListingInput, model_candidate: str) -> list[str]:
    listing_text = " ".join(
        [
            model_candidate or "",
            listing.sku_hint or "",
            listing.title or "",
            str(listing.extra.get("model_hint") or ""),
        ]
    )
    return tokenize_hdd_text(listing_text)


def tokenize_hdd_text(text: str) -> list[str]:
    normalized = normalize_hdd_spaces(text).upper()
    out: set[str] = set()
    for match in _RE_TOKEN.finditer(normalized):
        token = match.group(0).strip("-")
        if not token:
            continue
        out.add(token)
        if "-" in token:
            for part in token.split("-"):
                part = part.strip("-")
                if part:
                    out.add(part)
    return sorted(out)


def extract_hdd_identity_tokens(tokens: list[str]) -> set[str]:
    return {token for token in tokens if is_hdd_identity_token(token)}


def is_hdd_identity_token(token: str) -> bool:
    raw = (token or "").replace("-", "")
    if len(raw) < 5:
        return False
    return any("A" <= ch <= "Z" for ch in raw) and any("0" <= ch <= "9" for ch in raw)


def pick_hdd_model_candidate(listing: ListingInput) -> tuple[str, str]:
    model_hint = listing.extra.get("model_hint")
    if isinstance(model_hint, str) and model_hint.strip():
        return model_hint.strip(), "extra.model_hint"
    if (listing.sku_hint or "").strip():
        return listing.sku_hint.strip(), "sku_hint"
    return extract_hdd_title_fallback(listing.title), "title_fallback"


def extract_hdd_title_fallback(title: str) -> str:
    first_line = (title or "").splitlines()[0].strip() if title else ""
    if not first_line:
        return ""
    for match in _RE_PAREN.finditer(first_line):
        chunk = normalize_hdd_spaces(match.group(1))
        if not chunk:
            continue
        for token in tokenize_hdd_text(chunk):
            if is_hdd_identity_token(token):
                return token
    for token in tokenize_hdd_text(first_line):
        if is_hdd_identity_token(token):
            return token
    return first_line


def extract_hdd_matched_tokens(listing_tokens: list[str], page_tokens: list[str]) -> list[str]:
    return sorted(set(listing_tokens) & set(page_tokens))
