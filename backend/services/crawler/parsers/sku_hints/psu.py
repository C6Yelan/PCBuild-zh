# backend/services/crawler/parsers/sku_hints/psu.py
from .chassis_power_io.psu import extract_psu_hints, extract_psu_sku_hint

__all__ = ["extract_psu_hints", "extract_psu_sku_hint"]
