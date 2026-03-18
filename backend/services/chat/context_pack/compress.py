# backend/services/chat/context_pack/compress.py
from __future__ import annotations

import re
from typing import Any, Mapping

from backend.services.chat.context_pack.retrieval import P1RetrievalResult

_FIXED_FIELDS = (
    "part_id",
    "category",
    "display_name",
    "key_specs",
    "price",
    "source",
    "source_url",
    "snapshot_id",
    "run_id",
)
_LINEAGE_FIELDS = ("snapshot_id", "run_id")
_SPACE_RE = re.compile(r"\s+")


def _model_to_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        dumped = model_dump()
        if isinstance(dumped, Mapping):
            return dict(dumped)
    return {
        "part_id": getattr(value, "part_id", ""),
        "category": getattr(value, "category", ""),
        "display_name": getattr(value, "display_name", ""),
        "key_specs": getattr(value, "key_specs", {}),
        "price": getattr(value, "price", None),
        "source": getattr(value, "source", ""),
        "source_url": getattr(value, "source_url", ""),
        "snapshot_id": getattr(value, "snapshot_id", None),
        "run_id": getattr(value, "run_id", None),
    }


def _normalize_text(value: Any) -> str:
    return _SPACE_RE.sub(" ", str(value).strip())


def _normalize_whitelist(
    spec_whitelist_by_category: Mapping[str, list[str]] | None,
) -> dict[str, list[str]]:
    if not spec_whitelist_by_category:
        return {}
    normalized: dict[str, list[str]] = {}
    for category, keys in spec_whitelist_by_category.items():
        category_key = str(category).strip()
        if not category_key:
            continue
        unique_sorted = sorted({str(key).strip() for key in keys if str(key).strip()})
        normalized[category_key] = unique_sorted
    return normalized


def _extract_items_by_category(retrieval_result: Any) -> dict[str, list[Any]]:
    if isinstance(retrieval_result, P1RetrievalResult):
        return dict(retrieval_result.items_by_category)
    if isinstance(retrieval_result, Mapping):
        if "items_by_category" in retrieval_result and isinstance(retrieval_result["items_by_category"], Mapping):
            raw = retrieval_result["items_by_category"]
            return {str(k): list(v) for k, v in raw.items()}
        return {str(k): list(v) for k, v in retrieval_result.items()}
    items_by_category = getattr(retrieval_result, "items_by_category", {})
    if isinstance(items_by_category, Mapping):
        return {str(k): list(v) for k, v in items_by_category.items()}
    return {}


def _compress_specs(
    *,
    raw_specs: Any,
    category: str,
    whitelist_by_category: Mapping[str, list[str]],
    max_value_len: int,
    max_specs_per_part: int,
    reasons: set[str],
    dropped_specs: list[str],
    truncated_specs: dict[str, dict[str, int]],
) -> dict[str, str]:
    if not isinstance(raw_specs, Mapping):
        return {}

    specs_map = {str(key): raw_specs[key] for key in raw_specs}
    sorted_keys = sorted(specs_map.keys())
    category_whitelist = whitelist_by_category.get(category, [])

    if category_whitelist:
        allowed = set(category_whitelist)
        kept_keys = [key for key in sorted_keys if key in allowed]
        removed_by_whitelist = [key for key in sorted_keys if key not in allowed]
        if removed_by_whitelist:
            reasons.add("not_whitelisted")
            dropped_specs.extend(removed_by_whitelist)
    else:
        reasons.add("fallback_used")
        kept_keys = sorted_keys

    if len(kept_keys) > max_specs_per_part:
        reasons.add("too_many_specs")
        dropped_specs.extend(kept_keys[max_specs_per_part:])
        kept_keys = kept_keys[:max_specs_per_part]

    compressed_specs: dict[str, str] = {}
    for key in kept_keys:
        value = _normalize_text(specs_map.get(key, ""))
        if len(value) > max_value_len:
            reasons.add("value_too_long")
            compressed_specs[key] = value[:max_value_len]
            truncated_specs[key] = {"orig_len": len(value), "new_len": max_value_len}
            continue
        compressed_specs[key] = value
    return compressed_specs


def _build_drop_entry(
    *,
    dropped_fields: list[str],
    dropped_specs: list[str],
    truncated_specs: dict[str, dict[str, int]],
    reasons: set[str],
) -> dict[str, Any]:
    return {
        "dropped_fields": sorted(set(dropped_fields)),
        "dropped_specs": sorted(set(dropped_specs)),
        "truncated_specs": dict(sorted(truncated_specs.items())),
        "reason": sorted(reasons),
    }


def compress_candidates(
    retrieval_result: Any,
    *,
    spec_whitelist_by_category: Mapping[str, list[str]] | None,
    max_value_len: int,
    max_specs_per_part: int,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]]]:
    whitelist_by_category = _normalize_whitelist(spec_whitelist_by_category)
    normalized_max_value_len = max(1, int(max_value_len))
    normalized_max_specs = max(1, int(max_specs_per_part))
    items_by_category = _extract_items_by_category(retrieval_result)

    compressed_candidates: dict[str, list[dict[str, Any]]] = {}
    drop_log: dict[str, dict[str, Any]] = {}

    for category in sorted(items_by_category.keys()):
        compressed_items: list[dict[str, Any]] = []
        for index, raw_item in enumerate(items_by_category[category]):
            item = _model_to_dict(raw_item)
            dropped_fields = [field for field in item.keys() if field not in _FIXED_FIELDS]
            dropped_specs: list[str] = []
            truncated_specs: dict[str, dict[str, int]] = {}
            reasons: set[str] = set()

            compressed_specs = _compress_specs(
                raw_specs=item.get("key_specs", {}),
                category=category,
                whitelist_by_category=whitelist_by_category,
                max_value_len=normalized_max_value_len,
                max_specs_per_part=normalized_max_specs,
                reasons=reasons,
                dropped_specs=dropped_specs,
                truncated_specs=truncated_specs,
            )

            compressed_item: dict[str, Any] = {
                "part_id": str(item.get("part_id", "")),
                "category": str(item.get("category", category)),
                "display_name": str(item.get("display_name", "")),
                "key_specs": compressed_specs,
                "price": item.get("price"),
                "source": str(item.get("source", "")),
                "source_url": str(item.get("source_url", "")),
            }
            for lineage_key in _LINEAGE_FIELDS:
                lineage_value = item.get(lineage_key)
                if lineage_value is not None:
                    compressed_item[lineage_key] = str(lineage_value)

            compressed_items.append(compressed_item)
            part_id = compressed_item["part_id"] or f"{category}:{index}"
            drop_log[part_id] = _build_drop_entry(
                dropped_fields=dropped_fields,
                dropped_specs=dropped_specs,
                truncated_specs=truncated_specs,
                reasons=reasons,
            )

        compressed_candidates[category] = compressed_items

    return compressed_candidates, drop_log
