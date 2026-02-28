# backend/services/chat/context_pack/p2_compress.py
from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from backend.services.chat.contracts import PartCandidate

from .types import CompressedPart, DropLogItem

_VALUE_MAX_CHARS = 200
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1F\x7F]")
_NON_WORD_KEY_RE = re.compile(r"[^a-z0-9_]+")
_MULTI_SPACE_RE = re.compile(r"\s+")
_MULTI_UNDERSCORE_RE = re.compile(r"_+")
_EMPTY_TEXT_VALUES = {"", "n/a", "na", "none", "null", "-", "--"}

_CATEGORY_ALIASES: dict[str, str] = {
    "cpu": "cpu",
    "mb": "mb",
    "motherboard": "mb",
    "gpu": "gpu",
    "ram": "ram",
    "memory": "ram",
    "ssd": "ssd",
    "psu": "psu",
    "case": "case",
    "chassis": "case",
    "cooler": "cooler",
    "liquid_cooling": "liquid_cooling",
    "liquid-cooling": "liquid_cooling",
    "aio": "liquid_cooling",
    "hdd": "hdd",
    "case_fan": "case_fan",
    "fan": "case_fan",
    "expansion_card": "expansion_card",
}

_WHITELIST_BY_CATEGORY: dict[str, tuple[str, ...]] = {
    "cpu": ("socket", "cores", "threads", "base_clock_ghz", "boost_clock_ghz", "tdp_w", "igpu"),
    "mb": (
        "socket",
        "chipset",
        "form_factor",
        "ram_type",
        "ram_slots",
        "max_ram_gb",
        "m2_slots",
        "pcie_version",
        "wifi",
    ),
    "gpu": ("chipset", "vram_gb", "length_mm", "power_w", "pcie", "outputs"),
    "ram": ("ram_type", "speed_mhz", "capacity_gb", "modules", "voltage_v"),
    "ssd": ("interface", "form_factor", "capacity_gb", "read_mb_s", "write_mb_s"),
    "psu": ("watt_w", "efficiency", "modular", "atx_version"),
    "case": ("form_factor_support", "max_gpu_length_mm", "max_cooler_height_mm"),
    "cooler": ("cooler_type", "height_mm", "radiator_mm", "socket_support"),
    "liquid_cooling": ("cooler_type", "height_mm", "radiator_mm", "socket_support"),
    "hdd": ("interface", "capacity_gb", "rpm", "cache_mb"),
    "case_fan": ("size_mm", "bearing", "rpm", "airflow_cfm"),
    "expansion_card": ("interface", "chipset", "ports"),
}

_FALLBACK_WHITELIST: tuple[str, ...] = (
    "socket",
    "chipset",
    "form_factor",
    "capacity_gb",
    "speed_mhz",
    "interface",
    "length_mm",
)

_KEY_ALIASES_BY_CATEGORY: dict[str, dict[str, str]] = {
    "cpu": {
        "base_clock": "base_clock_ghz",
        "boost_clock": "boost_clock_ghz",
        "tdp": "tdp_w",
        "watt": "tdp_w",
        "integrated_graphics": "igpu",
        "i_gpu": "igpu",
    },
    "mb": {
        "ddr_gen": "ram_type",
        "memory_type": "ram_type",
        "memory_slots": "ram_slots",
        "slots": "ram_slots",
        "max_memory_gb": "max_ram_gb",
        "m_2_slots": "m2_slots",
        "pcie_gen": "pcie_version",
        "wifi_support": "wifi",
    },
    "gpu": {
        "vram": "vram_gb",
        "watt": "power_w",
        "tdp_w": "power_w",
        "pcie_gen": "pcie",
        "video_outputs": "outputs",
    },
    "ram": {
        "ddr_gen": "ram_type",
        "memory_type": "ram_type",
        "sticks": "modules",
        "capacity": "capacity_gb",
    },
    "ssd": {
        "type": "interface",
        "read_speed": "read_mb_s",
        "write_speed": "write_mb_s",
        "capacity": "capacity_gb",
    },
    "psu": {
        "watt": "watt_w",
        "efficiency_rating": "efficiency",
        "atx": "atx_version",
    },
    "case": {
        "supported_form_factor": "form_factor_support",
        "gpu_length_mm": "max_gpu_length_mm",
        "cooler_height_mm": "max_cooler_height_mm",
    },
    "cooler": {
        "type": "cooler_type",
        "height": "height_mm",
        "radiator_size": "radiator_mm",
        "socket": "socket_support",
    },
    "liquid_cooling": {
        "type": "cooler_type",
        "height": "height_mm",
        "radiator_size": "radiator_mm",
        "socket": "socket_support",
    },
}


def compress_specs(specs: dict[str, Any], category: str) -> tuple[dict[str, object], list[str], dict[str, str] | None]:
    canonical_category = _normalize_category(category)
    whitelist = _WHITELIST_BY_CATEGORY.get(canonical_category, _FALLBACK_WHITELIST)
    whitelist_set = set(whitelist)
    alias_map = _KEY_ALIASES_BY_CATEGORY.get(canonical_category, {})

    key_specs: dict[str, object] = {}
    dropped_keys: list[str] = []
    reasons: dict[str, str] = {}

    for raw_key, raw_value in specs.items():
        original_key = _normalize_key(raw_key)
        if not original_key:
            continue

        normalized_key = alias_map.get(original_key, original_key)
        if normalized_key not in whitelist_set:
            dropped_keys.append(normalized_key)
            reasons[normalized_key] = "not_whitelisted"
            continue

        value, reason, dropped = _normalize_spec_value(raw_value)
        if dropped:
            dropped_keys.append(normalized_key)
            reasons[normalized_key] = reason or "dropped"
            continue

        if reason:
            reasons[normalized_key] = reason
        key_specs[normalized_key] = value

    ordered_key_specs = {key: key_specs[key] for key in sorted(key_specs)}
    ordered_dropped_keys = _dedupe_preserve_order(dropped_keys)
    return ordered_key_specs, ordered_dropped_keys, reasons or None


def compress_candidates(
    candidates_by_category: dict[str, list[PartCandidate]] | dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, list[CompressedPart]], list[DropLogItem]]:
    compressed_by_category: dict[str, list[CompressedPart]] = {}
    drop_log: list[DropLogItem] = []

    for raw_bucket_category, raw_candidates in candidates_by_category.items():
        bucket_category = _as_non_empty_text(raw_bucket_category, fallback="UNKNOWN")
        compressed_parts: list[CompressedPart] = []

        for raw_candidate in raw_candidates:
            candidate = _coerce_candidate(raw_candidate)

            category = _as_non_empty_text(candidate.get("category"), fallback=bucket_category)
            part_id = _as_non_empty_text(candidate.get("part_id"), fallback=f"{category}-unknown")
            display_name = _as_non_empty_text(candidate.get("display_name"), fallback=part_id)

            raw_specs = candidate.get("key_specs")
            specs = raw_specs if isinstance(raw_specs, Mapping) else {}
            key_specs, dropped_keys, reasons = compress_specs(dict(specs), category=category)

            snapshot_id = _as_optional_text(candidate.get("snapshot_id"))
            run_id = _as_optional_text(candidate.get("run_id")) or snapshot_id

            compressed_part = CompressedPart(
                part_id=part_id,
                category=category,
                display_name=display_name,
                key_specs=key_specs,
                price=_as_optional_non_negative_int(candidate.get("price")),
                source=_as_optional_text(candidate.get("source")),
                source_url=_as_optional_text(candidate.get("source_url")),
                snapshot_id=snapshot_id,
                run_id=run_id,
            )
            compressed_parts.append(compressed_part)

            if dropped_keys or reasons:
                drop_log.append(
                    DropLogItem(
                        part_id=compressed_part.part_id,
                        category=compressed_part.category,
                        dropped_keys=dropped_keys,
                        reasons=reasons,
                    )
                )

        compressed_by_category[bucket_category] = compressed_parts

    return compressed_by_category, drop_log


def _normalize_category(raw_category: Any) -> str:
    normalized = _normalize_key(raw_category)
    if not normalized:
        return "unknown"
    return _CATEGORY_ALIASES.get(normalized, normalized)


def _normalize_key(raw_key: Any) -> str:
    text = _as_optional_text(raw_key)
    if text is None:
        return ""
    lowered = text.lower().replace("-", "_").replace("/", "_").replace(" ", "_")
    lowered = _NON_WORD_KEY_RE.sub("_", lowered)
    lowered = _MULTI_UNDERSCORE_RE.sub("_", lowered).strip("_")
    return lowered


def _normalize_spec_value(raw_value: Any) -> tuple[object, str | None, bool]:
    if raw_value is None:
        return "", "empty", True

    if isinstance(raw_value, bool):
        return raw_value, None, False

    if isinstance(raw_value, int | float):
        return raw_value, None, False

    if isinstance(raw_value, str):
        cleaned = _clean_text(raw_value)
        if _is_empty_text(cleaned):
            return "", "empty", True
        return _truncate_text(cleaned)

    if isinstance(raw_value, Mapping):
        flattened = _clean_text(json.dumps(raw_value, ensure_ascii=False, sort_keys=True))
        if _is_empty_text(flattened):
            return "", "empty", True
        value, reason, _ = _truncate_text(flattened)
        return value, reason or "non_scalar_stringified", False

    if isinstance(raw_value, Sequence) and not isinstance(raw_value, (bytes, bytearray)):
        normalized_items: list[str | int | float] = []
        had_too_long = False
        had_unsupported = False

        for item in raw_value:
            if isinstance(item, bool):
                had_unsupported = True
                continue
            if isinstance(item, int | float):
                normalized_items.append(item)
                continue
            if isinstance(item, str):
                cleaned = _clean_text(item)
                if _is_empty_text(cleaned):
                    continue
                value, reason, _ = _truncate_text(cleaned)
                if reason == "too_long":
                    had_too_long = True
                normalized_items.append(value)
                continue
            had_unsupported = True

        if not normalized_items:
            return "", "empty", True
        if had_too_long:
            return normalized_items, "too_long", False
        if had_unsupported:
            return normalized_items, "unsupported_type", False
        return normalized_items, None, False

    return "", "unsupported_type", True


def _truncate_text(text: str) -> tuple[str, str | None, bool]:
    if len(text) <= _VALUE_MAX_CHARS:
        return text, None, False
    return text[:_VALUE_MAX_CHARS], "too_long", False


def _clean_text(value: str) -> str:
    without_controls = _CONTROL_CHARS_RE.sub(" ", value)
    compact = _MULTI_SPACE_RE.sub(" ", without_controls).strip()
    return compact


def _is_empty_text(value: str) -> bool:
    return value.strip().lower() in _EMPTY_TEXT_VALUES


def _as_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = _clean_text(str(value))
    return cleaned or None


def _as_non_empty_text(value: Any, *, fallback: str) -> str:
    text = _as_optional_text(value)
    return text or fallback


def _as_optional_non_negative_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float):
        as_int = int(value)
        return as_int if as_int >= 0 else None
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            parsed = int(float(stripped))
        except ValueError:
            return None
        return parsed if parsed >= 0 else None
    return None


def _coerce_candidate(raw_candidate: PartCandidate | dict[str, Any]) -> dict[str, Any]:
    if isinstance(raw_candidate, PartCandidate):
        return raw_candidate.model_dump(mode="python")
    if isinstance(raw_candidate, Mapping):
        return dict(raw_candidate)
    model_dump = getattr(raw_candidate, "model_dump", None)
    if callable(model_dump):
        dumped = model_dump(mode="python")
        if isinstance(dumped, Mapping):
            return dict(dumped)
    raise TypeError(f"unsupported candidate type: {type(raw_candidate)!r}")


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out
