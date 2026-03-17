# backend/services/crawler/parsers/sku_hints/gpu.py
from .core_parts.gpu import extract_gpu_hints, extract_gpu_sku_hint

__all__ = ["extract_gpu_hints", "extract_gpu_sku_hint"]
