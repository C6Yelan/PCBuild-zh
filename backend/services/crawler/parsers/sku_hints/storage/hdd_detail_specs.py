from __future__ import annotations

import re

from ..common import head_before_brackets
from ..shared_specs import extract_capacity_gib
from ..shared_specs import normalized_title_line
from .hdd_identity_specs import (
    extract_hdd_model_token,
    extract_hdd_rescue_years,
    extract_hdd_segment_hint,
    extract_hdd_series_hint,
    extract_hdd_sku_hint,
    extract_hdd_warranty_years,
    infer_hdd_brand,
    infer_hdd_brand_from_model_token,
)

_RPM_RE = re.compile(r"(?P<rpm>\d{4,5})\s*轉")
_CACHE_MB_RE = re.compile(r"(?i)(?P<mb>\d{2,4})\s*MB\b")
_CACHE_M_RE = re.compile(r"(?i)(?P<mb>\d{2,4})\s*M\b")
_FORM_25_RE = re.compile(r"2\.5吋|2\.5\"", flags=re.IGNORECASE)
_FORM_35_RE = re.compile(r"3\.5吋|3\.5\"", flags=re.IGNORECASE)
_THICKNESS_RE = re.compile(r"(?i)(?P<mm>\d+(?:\.\d+)?)\s*mm\b")
_SATA_RE = re.compile(r"(?i)\bSATA\b")
_SAS_RE = re.compile(r"(?i)\bSAS\b")
_USB_RE = re.compile(r"(?i)\bUSB\b|Type-?C")
_LIMIT_RE = re.compile(r"(限組裝|限購)")


def _pick_hint(*candidates: str | None) -> str:
    for candidate in candidates:
        if candidate is not None:
            value = str(candidate).strip()
            if value:
                return value
    return ""


def extract_hdd_hints(title: str) -> tuple[str | None, dict[str, object]]:
    text = title or ""
    line = normalized_title_line(text)
    head = head_before_brackets(line)
    title_first_line = normalized_title_line(text)

    model_token = _pick_hint(extract_hdd_model_token(line), extract_hdd_model_token(head), extract_hdd_model_token(text))
    model_hint = _pick_hint(model_token, head, line, title_first_line, "UNKNOWN-HDD")
    sku_hint = _pick_hint(model_token, model_hint, head, line, title_first_line, "UNKNOWN-HDD")

    brand_hint = infer_hdd_brand(head or line)
    if brand_hint is None:
        brand_hint = infer_hdd_brand(text)
    if brand_hint is None:
        brand_hint = infer_hdd_brand_from_model_token(model_token)
    if brand_hint is None:
        brand_hint = infer_hdd_brand_from_model_token(model_hint)

    capacity_gib = extract_capacity_gib(head) or extract_capacity_gib(line)

    rpm_hint = None
    match = _RPM_RE.search(line)
    if match:
        rpm_hint = int(match.group("rpm"))

    cache_mb_hint = None
    match = _CACHE_MB_RE.search(line)
    if match:
        cache_mb_hint = int(match.group("mb"))
    else:
        match = _CACHE_M_RE.search(line)
        if match:
            cache_mb_hint = int(match.group("mb"))

    form_factor_hint = None
    if _FORM_25_RE.search(line):
        form_factor_hint = '2.5"'
    elif _FORM_35_RE.search(line):
        form_factor_hint = '3.5"'

    thickness_mm_hint = None
    if form_factor_hint == '2.5"':
        match = _THICKNESS_RE.search(line)
        if match:
            thickness_mm_hint = float(match.group("mm"))
            if thickness_mm_hint.is_integer():
                thickness_mm_hint = int(thickness_mm_hint)

    interface_hint = None
    if _SATA_RE.search(line):
        interface_hint = "SATA"
    elif _SAS_RE.search(line):
        interface_hint = "SAS"
    elif _USB_RE.search(line):
        interface_hint = "USB"

    if interface_hint is None and form_factor_hint in ('2.5"', '3.5"'):
        interface_hint = "SATA"

    limit_hint = None
    match = _LIMIT_RE.search(line)
    if match:
        limit_hint = match.group(1)

    extra = {
        "brand_hint": brand_hint,
        "model_hint": model_hint,
        "capacity_gib": capacity_gib,
        "form_factor_hint": form_factor_hint,
        "thickness_mm_hint": thickness_mm_hint,
        "interface_hint": interface_hint,
        "rpm_hint": rpm_hint,
        "cache_mb_hint": cache_mb_hint,
        "series_hint": extract_hdd_series_hint(line),
        "segment_hint": extract_hdd_segment_hint(line),
        "rescue_years": extract_hdd_rescue_years(line),
        "warranty_years": extract_hdd_warranty_years(line),
        "limit_hint": limit_hint,
    }
    extra["model_hint"] = model_hint
    extra = {key: value for key, value in extra.items() if value is not None}
    return sku_hint, extra
