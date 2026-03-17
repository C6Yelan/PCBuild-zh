from .mb_detail_specs import extract_mb_spec_hints
from .mb_identity_specs import extract_mb_head, extract_mb_sku_model_hint, infer_mb_brand_hint

__all__ = [
    "extract_mb_head",
    "extract_mb_spec_hints",
    "extract_mb_sku_model_hint",
    "infer_mb_brand_hint",
]
