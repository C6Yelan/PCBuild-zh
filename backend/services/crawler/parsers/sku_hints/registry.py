# backend/services/crawler/parsers/sku_hints/registry.py
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from backend.services.crawler.registry_primitives import (
    lookup_registry_entry,
    normalize_registry_key,
    register_aliases,
)

from .case import extract_case_hints, extract_case_sku_hint
from .case_fan import extract_case_fan_listing_hints, extract_case_fan_sku_hint
from .cpu import extract_cpu_hints, extract_cpu_sku_hint
from .cooler import extract_cooler_hints, extract_cooler_sku_hint
from .gpu import extract_gpu_hints
from .hdd import extract_hdd_hints, extract_hdd_sku_hint
from .liquid_cooling import extract_liquid_cooling_hints, extract_liquid_cooling_sku_hint
from .mb import extract_mb_hints, extract_mb_sku_hint
from .expansion_card import extract_expansion_card_hints, extract_expansion_card_sku_hint
from .psu import extract_psu_hints, extract_psu_sku_hint
from .ram import extract_ram_hints, extract_ram_sku_hint
from .ssd import extract_ssd_hints, extract_ssd_sku_hint


@dataclass(frozen=True)
class ListingHints: # 從品名抽出的各種提示（型號、是否為套裝等），並統一回傳格式。
    sku_hint: str | None
    extra: dict[str, object] | None
    is_bundle: bool

SkuHintExtractor = Callable[[str], str | None]
BasicHintsExtractor = Callable[[str], tuple[str | None, dict[str, Any]]]
DetailHintsExtractor = Callable[[str, list[str] | None], tuple[str | None, dict[str, Any]]]
ListingHintsExtractor = Callable[[str, list[str] | None], ListingHints]


@dataclass(frozen=True)
class _CategoryHintHandler:
    sku_hint: SkuHintExtractor
    listing_hints: ListingHintsExtractor


def _extract_gpu_sku_hint_from_hints(title: str) -> str | None:
    sku_hint, _extra = extract_gpu_hints(title)
    return sku_hint


def _make_listing_hints(
    sku_hint: str | None,
    extra: dict[str, Any],
    *,
    bundle_from_extra: bool,
) -> ListingHints:
    is_bundle = bool(extra.get("is_bundle")) if bundle_from_extra else False
    return ListingHints(sku_hint=sku_hint, extra=extra, is_bundle=is_bundle)


def _build_basic_listing_hints(
    extractor: BasicHintsExtractor,
    *,
    bundle_from_extra: bool,
) -> ListingHintsExtractor:
    def _listing_hints(title: str, _desc_lines: list[str] | None) -> ListingHints:
        sku_hint, extra = extractor(title)
        return _make_listing_hints(sku_hint, extra, bundle_from_extra=bundle_from_extra)

    return _listing_hints


def _build_detail_listing_hints(
    extractor: DetailHintsExtractor,
    *,
    bundle_from_extra: bool,
) -> ListingHintsExtractor:
    def _listing_hints(title: str, desc_lines: list[str] | None) -> ListingHints:
        sku_hint, extra = extractor(title, desc_lines)
        return _make_listing_hints(sku_hint, extra, bundle_from_extra=bundle_from_extra)

    return _listing_hints


_CATEGORY_HINT_HANDLERS: dict[str, _CategoryHintHandler] = {}

register_aliases(
    _CATEGORY_HINT_HANDLERS,
    ("CPU",),
    _CategoryHintHandler(
        sku_hint=extract_cpu_sku_hint,
        listing_hints=_build_basic_listing_hints(extract_cpu_hints, bundle_from_extra=True),
    ),
)
_mb_handler = _CategoryHintHandler(
    sku_hint=extract_mb_sku_hint,
    listing_hints=_build_basic_listing_hints(extract_mb_hints, bundle_from_extra=True),
)
register_aliases(_CATEGORY_HINT_HANDLERS, ("MB", "MOTHERBOARD"), _mb_handler)
register_aliases(
    _CATEGORY_HINT_HANDLERS,
    ("GPU",),
    _CategoryHintHandler(
        sku_hint=_extract_gpu_sku_hint_from_hints,
        listing_hints=_build_basic_listing_hints(extract_gpu_hints, bundle_from_extra=True),
    ),
)
register_aliases(
    _CATEGORY_HINT_HANDLERS,
    ("RAM",),
    _CategoryHintHandler(
        sku_hint=extract_ram_sku_hint,
        listing_hints=_build_basic_listing_hints(extract_ram_hints, bundle_from_extra=True),
    ),
)
register_aliases(
    _CATEGORY_HINT_HANDLERS,
    ("SSD",),
    _CategoryHintHandler(
        sku_hint=extract_ssd_sku_hint,
        listing_hints=_build_basic_listing_hints(extract_ssd_hints, bundle_from_extra=False),
    ),
)
register_aliases(
    _CATEGORY_HINT_HANDLERS,
    ("HDD",),
    _CategoryHintHandler(
        sku_hint=extract_hdd_sku_hint,
        listing_hints=_build_basic_listing_hints(extract_hdd_hints, bundle_from_extra=False),
    ),
)
register_aliases(
    _CATEGORY_HINT_HANDLERS,
    ("COOLER",),
    _CategoryHintHandler(
        sku_hint=extract_cooler_sku_hint,
        listing_hints=_build_basic_listing_hints(extract_cooler_hints, bundle_from_extra=True),
    ),
)
register_aliases(
    _CATEGORY_HINT_HANDLERS,
    ("LIQUID_COOLING",),
    _CategoryHintHandler(
        sku_hint=extract_liquid_cooling_sku_hint,
        listing_hints=_build_basic_listing_hints(extract_liquid_cooling_hints, bundle_from_extra=True),
    ),
)
register_aliases(
    _CATEGORY_HINT_HANDLERS,
    ("CASE",),
    _CategoryHintHandler(
        sku_hint=extract_case_sku_hint,
        listing_hints=_build_detail_listing_hints(extract_case_hints, bundle_from_extra=True),
    ),
)
register_aliases(
    _CATEGORY_HINT_HANDLERS,
    ("PSU",),
    _CategoryHintHandler(
        sku_hint=extract_psu_sku_hint,
        listing_hints=_build_detail_listing_hints(extract_psu_hints, bundle_from_extra=True),
    ),
)
register_aliases(
    _CATEGORY_HINT_HANDLERS,
    ("CASE_FAN",),
    _CategoryHintHandler(
        sku_hint=extract_case_fan_sku_hint,
        listing_hints=_build_detail_listing_hints(extract_case_fan_listing_hints, bundle_from_extra=True),
    ),
)
register_aliases(
    _CATEGORY_HINT_HANDLERS,
    ("EXPANSION_CARD",),
    _CategoryHintHandler(
        sku_hint=extract_expansion_card_sku_hint,
        listing_hints=_build_detail_listing_hints(extract_expansion_card_hints, bundle_from_extra=True),
    ),
)


def _get_category_hint_handler(category: str | None) -> _CategoryHintHandler | None:
    category_key = normalize_registry_key(category, case="upper", strip=False)
    return lookup_registry_entry(_CATEGORY_HINT_HANDLERS, category_key, default=None)


def extract_sku_hint(category: str | None, title: str) -> str | None: # 只回傳 sku_hint(型號提示)，不回傳 extra。
    handler = _get_category_hint_handler(category)
    if handler is None:
        return None
    return handler.sku_hint(title)


def extract_listing_hints(category: str | None, title: str, desc_lines: list[str] | None = None) -> ListingHints: # 回傳包含 sku_hint、extra、is_bundle 的 ListingHints。
    handler = _get_category_hint_handler(category)
    if handler is None:
        return ListingHints(sku_hint=extract_sku_hint(category, title), extra=None, is_bundle=False)
    return handler.listing_hints(title, desc_lines)
