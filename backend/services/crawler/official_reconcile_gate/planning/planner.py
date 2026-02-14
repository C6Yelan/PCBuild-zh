# backend/services/crawler/official_reconcile_gate/planning/planner.py
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from typing import Any

from .brand import resolve_brand
from .registry import get_allowed_domains
from .types import OfficialLookupPlan, OfficialRegistry, RetailCandidate

_SPACE_RE = re.compile(r"\s+", flags=re.UNICODE)
_BRACKET_SPLIT_RE = re.compile(r"[（(【\[]", flags=re.UNICODE)
_SPEC_SPLIT_RE = re.compile(r"[：:]", flags=re.UNICODE)


def normalize_retail_candidate(obj: Any, *, where: str = "input") -> RetailCandidate:
    if not isinstance(obj, Mapping):
        raise ValueError(f"expected object at {where}, got {type(obj).__name__}")

    source = _require_string(obj, "source", where=where)
    category = _require_string(obj, "category", where=where)
    title = _require_string(obj, "title", where=where)
    url = _require_string(obj, "url", where=where)

    sku_hint_value = obj.get("sku_hint", "")
    if sku_hint_value is None:
        raise ValueError(f"sku_hint must not be null at {where}")
    if not isinstance(sku_hint_value, str):
        raise ValueError(f"sku_hint must be string at {where}")

    extra_value = obj.get("extra", {})
    if extra_value is None:
        extra_value = {}
    if not isinstance(extra_value, Mapping):
        raise ValueError(f"extra must be object at {where}")
    extra: dict[str, Any] = dict(extra_value)

    for key in ("brand_hint", "maker_hint", "model_hint", "product_model_hint"):
        if key in obj and key not in extra:
            extra[key] = obj[key]

    return RetailCandidate(
        source=source,
        category=category,
        title=title,
        url=url,
        sku_hint=sku_hint_value,
        extra=extra,
    )


def build_official_lookup_plan(
    obj: Any,
    registry: OfficialRegistry,
    *,
    where: str = "input",
) -> OfficialLookupPlan:
    candidate = normalize_retail_candidate(obj, where=where)
    brand = resolve_brand(candidate, registry)
    allowed_domains = get_allowed_domains(registry, brand.brand_key)
    query_terms = _build_query_terms(candidate)
    decision, decision_notes = _resolve_decision(brand.brand_key, allowed_domains)

    return OfficialLookupPlan(
        retail_url=candidate["url"],
        source=candidate["source"],
        category=candidate["category"],
        title=candidate["title"],
        sku_hint=candidate["sku_hint"],
        brand_key=brand.brand_key,
        brand_source=brand.brand_source,
        brand_raw=brand.brand_raw,
        allowed_domains=allowed_domains,
        query_terms=query_terms,
        decision=decision,
        decision_notes=decision_notes,
    )


def build_official_lookup_plans(
    rows: Sequence[Any],
    registry: OfficialRegistry,
) -> list[OfficialLookupPlan]:
    plans: list[OfficialLookupPlan] = []
    for idx, obj in enumerate(rows):
        plans.append(build_official_lookup_plan(obj, registry, where=f"index {idx}"))
    return plans


def plan_to_dict(plan: OfficialLookupPlan) -> dict[str, Any]:
    return asdict(plan)


def _build_query_terms(candidate: RetailCandidate) -> list[str]:
    terms: list[str] = []
    sku_hint = candidate.get("sku_hint", "")
    if isinstance(sku_hint, str) and sku_hint.strip():
        terms.append(sku_hint)

    extra = candidate.get("extra", {})
    if isinstance(extra, Mapping):
        for key in ("model_hint", "product_model_hint"):
            value = extra.get(key)
            if isinstance(value, str) and value.strip():
                terms.append(value)

    cleaned: list[str] = []
    seen: set[str] = set()
    for term in terms:
        normalized = _clean_query_term(term)
        if normalized and normalized not in seen:
            seen.add(normalized)
            cleaned.append(normalized)
    return cleaned


def _clean_query_term(raw: str) -> str:
    text = raw.replace("\u3000", " ")
    text = _SPEC_SPLIT_RE.split(text, maxsplit=1)[0]
    text = _BRACKET_SPLIT_RE.split(text, maxsplit=1)[0]
    return _SPACE_RE.sub(" ", text).strip()


def _resolve_decision(brand_key: str | None, allowed_domains: list[str]) -> tuple[str, str]:
    if brand_key is None:
        return ("quarantine", "brand unresolved; cannot plan official lookup")
    if not allowed_domains:
        return ("needs_registry", f"brand '{brand_key}' has empty allowed_domains")
    return ("ok", f"brand '{brand_key}' resolved with {len(allowed_domains)} allowed domain(s)")


def _require_string(obj: Mapping[str, Any], key: str, *, where: str) -> str:
    if key not in obj:
        raise ValueError(f"missing required field {key!r} at {where}")
    value = obj[key]
    if not isinstance(value, str):
        raise ValueError(f"field {key!r} must be string at {where}")
    return value
