# backend/services/crawler/parsers/sku_hints/registry.py
from __future__ import annotations

from .cpu import extract_cpu_sku_hint
from .mb import extract_mb_sku_hint

def extract_sku_hint(category: str | None, title: str) -> str | None:
    c = (category or "").upper()
    if c == "CPU":
        return extract_cpu_sku_hint(title)
    if c in ("MB", "MOTHERBOARD"):
        return extract_mb_sku_hint(title)
    return None
