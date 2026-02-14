# backend/services/crawler/official_reconcile_gate/planning/brand.py
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from .registry import normalize_brand_token, resolve_brand_key
from .types import BrandResolution, OfficialRegistry

_SPACE_RE = re.compile(r"\s+", flags=re.UNICODE)
_TITLE_SPLIT_RE = re.compile(r"[\r\n/|｜]", flags=re.UNICODE)
_BRACKET_SPLIT_RE = re.compile(r"[（(【\[]", flags=re.UNICODE)
_COLON_SPLIT_RE = re.compile(r"[：:]", flags=re.UNICODE)


def resolve_brand(candidate: Mapping[str, Any], registry: OfficialRegistry) -> BrandResolution:
    extra = candidate.get("extra")
    if not isinstance(extra, Mapping):
        extra = {}

    brand_hint = _as_non_empty_text(extra.get("brand_hint"))
    if brand_hint is not None:
        return BrandResolution(
            brand_key=resolve_brand_key(registry, brand_hint),
            brand_source="extra.brand_hint",
            brand_raw=brand_hint,
        )

    maker_hint = _as_non_empty_text(extra.get("maker_hint"))
    if maker_hint is not None:
        return BrandResolution(
            brand_key=resolve_brand_key(registry, maker_hint),
            brand_source="extra.maker_hint",
            brand_raw=maker_hint,
        )

    title = candidate.get("title")
    sku_hint = candidate.get("sku_hint")
    hit = _find_brand_from_title_or_sku_hint(
        title if isinstance(title, str) else "",
        sku_hint if isinstance(sku_hint, str) else "",
        registry,
    )
    if hit is not None:
        return BrandResolution(
            brand_key=hit[0],
            brand_source="title_or_sku_hint+registry_alias",
            brand_raw=hit[1],
        )

    return BrandResolution(brand_key=None, brand_source="unknown", brand_raw=None)


def _as_non_empty_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = _SPACE_RE.sub(" ", value.replace("\u3000", " ")).strip()
    return text or None


def _find_brand_from_title_or_sku_hint(
    title: str,
    sku_hint: str,
    registry: OfficialRegistry,
) -> tuple[str, str] | None:
    candidates = [_head_text(title), _head_text(sku_hint)]
    alias_entries = _sorted_alias_entries(registry)
    for raw_text in candidates:
        if not raw_text:
            continue
        normalized_text = normalize_brand_token(raw_text)
        if not normalized_text:
            continue
        for normalized_alias, brand_key, alias_raw in alias_entries:
            if normalized_text.startswith(normalized_alias):
                return (brand_key, alias_raw)
    return None


def _head_text(text: str) -> str:
    value = _as_non_empty_text(text)
    if value is None:
        return ""
    value = _TITLE_SPLIT_RE.split(value, maxsplit=1)[0]
    value = _BRACKET_SPLIT_RE.split(value, maxsplit=1)[0]
    value = _COLON_SPLIT_RE.split(value, maxsplit=1)[0]
    return _as_non_empty_text(value) or ""


def _sorted_alias_entries(registry: OfficialRegistry) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for entry in registry.brands:
        for alias_raw in [entry.brand_key, *entry.brand_aliases]:
            text = _as_non_empty_text(alias_raw)
            if text is None:
                continue
            normalized_alias = normalize_brand_token(text)
            key = (entry.brand_key, normalized_alias)
            if not normalized_alias or key in seen:
                continue
            seen.add(key)
            rows.append((normalized_alias, entry.brand_key, text))
    rows.sort(key=lambda x: len(x[0]), reverse=True)
    return rows
