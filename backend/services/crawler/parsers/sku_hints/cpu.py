# backend/services/crawler/parsers/sku_hints/cpu.py
from __future__ import annotations

import re

from .common import first_line

_CPU_SKU_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])("
    r"(?:i[3579]-\d{4,5}[a-z0-9]{0,6})|"
    r"(?:core\s+ultra\s+\d+\s+\d{3}[a-z0-9]{0,6})|"
    r"(?:ryzen\s+[3579]\s+\d{4,5}[a-z0-9]{0,6})|"
    r"(?:amd\s+)?r[3579]\s*\d{4,5}[a-z0-9]{0,6}|"
    r"(?:xeon\s+w\d+-\d{4,5}[a-z0-9]{0,6})|"
    r"(?:ryzen\s+tr\s+(?:pro\s+)?\d{4,5}[a-z0-9]{0,6})|"
    r"(?:threadripper\s+(?:pro\s+)?\d{4,5}[a-z0-9]{0,6})"
    r")(?=[^A-Za-z0-9]|$)"
)

_AMD_HINT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])("
    r"(?:ryzen|threadripper|epyc|athlon)|"
    r"(?:amd\s+)?r[3579]\s*\d{4,5}[a-z0-9]{0,6}"
    r")(?=[^A-Za-z0-9]|$)"
)
_INTEL_HINT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])("
    r"(?:core\s+ultra\s+\d+\s+\d{3}[a-z0-9]{0,6})|"
    r"(?:core\s+i\d)|"
    r"(?:i[3579]-\d{4,5}[a-z0-9]{0,6})|"
    r"(?:xeon|pentium|celeron|atom|intel)"
    r")(?=[^A-Za-z0-9]|$)"
)
_ACCESSORY_RE = re.compile(r"(?i)(水冷|散熱器?|冷卻|優惠加購|加購|(?<![含無附])風扇)")

def _infer_brand_hint(title: str, sku_hint: str | None) -> str | None:
    text = (sku_hint or title or "").strip()
    if not text:
        return None
    if _AMD_HINT_RE.search(text):
        return "AMD"
    if _INTEL_HINT_RE.search(text):
        return "Intel"
    return None

def extract_cpu_sku_hint(title: str) -> str | None:
    line = first_line(title)
    m = _CPU_SKU_RE.search(line)
    return m.group(1) if m else None

def extract_cpu_hints(title: str) -> tuple[str | None, dict[str, object]]:
    line = first_line(title)
    sku_hint = extract_cpu_sku_hint(line)
    is_accessory = sku_hint is None and bool(_ACCESSORY_RE.search(line))
    extra = {
        "brand_hint": _infer_brand_hint(line, sku_hint),
        "model_hint": sku_hint,
        "is_bundle": False,
        "is_accessory": is_accessory,
    }
    return sku_hint, extra
