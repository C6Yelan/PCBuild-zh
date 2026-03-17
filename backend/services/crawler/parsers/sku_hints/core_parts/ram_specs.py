# backend/services/crawler/parsers/sku_hints/core_parts/ram_specs.py
from .ram_detail_specs import extract_ram_hints
from .ram_identity_specs import extract_ram_sku_hint

__all__ = ["extract_ram_hints", "extract_ram_sku_hint"]
