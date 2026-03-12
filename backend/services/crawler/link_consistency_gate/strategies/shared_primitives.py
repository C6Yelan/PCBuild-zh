# backend/services/crawler/link_consistency_gate/strategies/shared_primitives.py
"""Shared low-risk text and evidence primitives for link consistency strategies."""

from __future__ import annotations

import re
from typing import Any, Callable

_RE_WS = re.compile(r"\s+", flags=re.UNICODE)
_RE_MODEL_TOKEN = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*", flags=re.UNICODE)


def normalize_spaces(text: str) -> str:
    normalized = (text or "").replace("\u3000", " ").replace("\xa0", " ")
    return _RE_WS.sub(" ", normalized).strip()


def compose_page_text(
    *parts: str | None,
    normalize: Callable[[str], str] | None = None,
) -> str:
    text = " ".join(part for part in parts if part).strip()
    if normalize is not None:
        return normalize(text)
    return text


def tokenize_model_tokens(
    text: str,
    *,
    normalize: Callable[[str], str],
    join_hyphen_parts: bool = False,
) -> list[str]:
    normalized = normalize(text)
    tokens: set[str] = set()

    for match in _RE_MODEL_TOKEN.finditer(normalized):
        token = match.group(0).strip("-")
        if not token:
            continue
        tokens.add(token)
        if "-" not in token:
            continue

        parts: list[str] = []
        for part in token.split("-"):
            part = part.strip("-")
            if not part:
                continue
            tokens.add(part)
            parts.append(part)
        if join_hyphen_parts and parts:
            tokens.add("".join(parts))

    return sorted(tokens)


def build_evidence(
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
