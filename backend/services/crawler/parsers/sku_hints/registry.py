# backend/services/crawler/parsers/sku_hints/registry.py
from __future__ import annotations

from dataclasses import dataclass

from .case import extract_case_hints, extract_case_sku_hint
from .case_fan import extract_case_fan_listing_hints, extract_case_fan_sku_hint
from .cpu import extract_cpu_hints, extract_cpu_sku_hint
from .cooler import extract_cooler_hints, extract_cooler_sku_hint
from .gpu import extract_gpu_hints
from .hdd import extract_hdd_hints, extract_hdd_sku_hint
from .liquid_cooling import extract_liquid_cooling_hints, extract_liquid_cooling_sku_hint
from .mb import extract_mb_hints, extract_mb_sku_hint
from .psu import extract_psu_hints, extract_psu_sku_hint
from .ram import extract_ram_hints, extract_ram_sku_hint
from .ssd import extract_ssd_hints, extract_ssd_sku_hint


@dataclass(frozen=True)
class ListingHints: # 從品名抽出的各種提示（型號、是否為套裝等），並統一回傳格式。
    sku_hint: str | None
    extra: dict[str, object] | None
    is_bundle: bool

def extract_sku_hint(category: str | None, title: str) -> str | None: # 只回傳 sku_hint(型號提示)，不回傳 extra。
    c = (category or "").upper()
    if c == "CPU":
        return extract_cpu_sku_hint(title)
    if c in ("MB", "MOTHERBOARD"):
        return extract_mb_sku_hint(title)
    if c == "GPU":
        sku_hint, _extra = extract_gpu_hints(title)
        return sku_hint
    if c == "RAM":
        return extract_ram_sku_hint(title)
    if c == "SSD":
        return extract_ssd_sku_hint(title)
    if c == "HDD":
        return extract_hdd_sku_hint(title)
    if c == "COOLER":
        return extract_cooler_sku_hint(title)
    if c == "LIQUID_COOLING":
        return extract_liquid_cooling_sku_hint(title)
    if c == "CASE":
        return extract_case_sku_hint(title)
    if c == "PSU":
        return extract_psu_sku_hint(title)
    if c == "CASE_FAN":
        return extract_case_fan_sku_hint(title)
    return None


def extract_listing_hints(category: str | None, title: str, desc_lines: list[str] | None = None) -> ListingHints: # 回傳包含 sku_hint、extra、is_bundle 的 ListingHints。
    c = (category or "").upper()
    if c == "CPU":
        sku_hint, extra = extract_cpu_hints(title)
        return ListingHints(sku_hint=sku_hint, extra=extra, is_bundle=bool(extra.get("is_bundle")))
    if c in ("MB", "MOTHERBOARD"):
        sku_hint, extra = extract_mb_hints(title)
        return ListingHints(sku_hint=sku_hint, extra=extra, is_bundle=bool(extra.get("is_bundle")))
    if c == "GPU":
        sku_hint, extra = extract_gpu_hints(title)
        return ListingHints(sku_hint=sku_hint, extra=extra, is_bundle=bool(extra.get("is_bundle")))
    if c == "RAM":
        sku_hint, extra = extract_ram_hints(title)
        return ListingHints(sku_hint=sku_hint, extra=extra, is_bundle=bool(extra.get("is_bundle")))
    if c == "SSD":
        sku_hint, extra = extract_ssd_hints(title)
        return ListingHints(sku_hint=sku_hint, extra=extra, is_bundle=False)
    if c == "HDD":
        sku_hint, extra = extract_hdd_hints(title)
        return ListingHints(sku_hint=sku_hint, extra=extra, is_bundle=False)
    if c == "COOLER":
        sku_hint, extra = extract_cooler_hints(title)
        return ListingHints(sku_hint=sku_hint, extra=extra, is_bundle=bool(extra.get("is_bundle")))
    if c == "LIQUID_COOLING":
        sku_hint, extra = extract_liquid_cooling_hints(title)
        return ListingHints(sku_hint=sku_hint, extra=extra, is_bundle=bool(extra.get("is_bundle")))
    if c == "CASE":
        sku_hint, extra = extract_case_hints(title, desc_lines)
        return ListingHints(sku_hint=sku_hint, extra=extra, is_bundle=bool(extra.get("is_bundle")))
    if c == "PSU":
        sku_hint, extra = extract_psu_hints(title, desc_lines)
        return ListingHints(sku_hint=sku_hint, extra=extra, is_bundle=bool(extra.get("is_bundle")))
    if c == "CASE_FAN":
        sku_hint, extra = extract_case_fan_listing_hints(title, desc_lines)
        return ListingHints(sku_hint=sku_hint, extra=extra, is_bundle=bool(extra.get("is_bundle")))
    return ListingHints(sku_hint=extract_sku_hint(category, title), extra=None, is_bundle=False)
