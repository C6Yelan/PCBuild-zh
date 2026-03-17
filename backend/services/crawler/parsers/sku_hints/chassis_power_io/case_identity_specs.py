# backend/services/crawler/parsers/sku_hints/chassis_power_io/case_identity_specs.py
from __future__ import annotations

import re

from ..shared_specs import extract_brand_hint as shared_extract_brand_hint
from ..shared_specs import extract_model_hint as shared_extract_model_hint

_MODEL_BUNDLE_SPLIT_RE = re.compile(r"\s+[+＋]\s+")
_MODEL_TRAILING_SPEC_RE = re.compile(
    r"(?:\s*(?:顯卡長|卡長|卡|CPU高|U高)(?:\s*\d+(?:\.\d+)?(?:\([^)]*\))?)?)+\s*$",
    flags=re.IGNORECASE,
)


def extract_case_model_hint(text: str) -> str | None:
    return shared_extract_model_hint(
        text,
        strip_bracket_tags=True,
        bundle_split_re=_MODEL_BUNDLE_SPLIT_RE,
        clean_pattern=_MODEL_TRAILING_SPEC_RE,
    )


def extract_case_brand_hint(text: str) -> str | None:
    return shared_extract_brand_hint(
        text,
        strip_bracket_tags=True,
        allow_cjk_prefix=True,
    )
