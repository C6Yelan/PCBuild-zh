# backend/services/crawler/parsers/sku_hints/registry.py
from __future__ import annotations

from dataclasses import dataclass

from .sku_hints.cpu import extract_cpu_hints, extract_cpu_sku_hint
from .sku_hints.gpu import extract_gpu_hints
from .sku_hints.mb import extract_mb_sku_hint
from .sku_hints.ram import extract_ram_hints


@dataclass(frozen=True)
class ListingHints:
    sku_hint: str | None
    extra: dict[str, object] | None
    is_bundle: bool

def extract_sku_hint(category: str | None, title: str) -> str | None:
    c = (category or "").upper()
    if c == "CPU":
        return extract_cpu_sku_hint(title)
    if c in ("MB", "MOTHERBOARD"):
        return extract_mb_sku_hint(title)
    if c == "GPU":
        sku_hint, _extra = extract_gpu_hints(title)
        return sku_hint
    if c in ("RAM", "DRAM", "MEMORY"):
        sku_hint, _extra = extract_ram_hints(title)
        return sku_hint
    return None


def extract_listing_hints(category: str | None, title: str) -> ListingHints:
    c = (category or "").upper()
    if c == "CPU":
        sku_hint, extra = extract_cpu_hints(title)
        return ListingHints(sku_hint=sku_hint, extra=extra, is_bundle=bool(extra.get("is_bundle")))
    if c in ("MB", "MOTHERBOARD"):
        sku_hint = extract_mb_sku_hint(title)
        return ListingHints(sku_hint=sku_hint, extra=None, is_bundle=False)
    if c == "GPU":
        sku_hint, extra = extract_gpu_hints(title)
        return ListingHints(sku_hint=sku_hint, extra=extra, is_bundle=bool(extra.get("is_bundle")))
    if c in ("RAM", "DRAM", "MEMORY"):
        sku_hint, extra = extract_ram_hints(title)
        return ListingHints(sku_hint=sku_hint, extra=extra, is_bundle=bool(extra.get("is_bundle")))
    return ListingHints(sku_hint=extract_sku_hint(category, title), extra=None, is_bundle=False)
