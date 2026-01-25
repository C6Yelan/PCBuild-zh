# backend/services/crawler/parsers/sku_hints/registry.py
from __future__ import annotations

from dataclasses import dataclass

from .cpu import extract_cpu_hints, extract_cpu_sku_hint
from .gpu import extract_gpu_hints
from .hdd import extract_hdd_hints, extract_hdd_sku_hint
from .mb import extract_mb_hints, extract_mb_sku_hint
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
    return None


def extract_listing_hints(category: str | None, title: str) -> ListingHints: # 回傳包含 sku_hint、extra、is_bundle 的 ListingHints。
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
    return ListingHints(sku_hint=extract_sku_hint(category, title), extra=None, is_bundle=False)
