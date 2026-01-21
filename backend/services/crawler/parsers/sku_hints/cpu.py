# backend/services/crawler/parsers/sku_hints/cpu.py
from __future__ import annotations

import re

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

def extract_cpu_sku_hint(title: str) -> str | None:
    m = _CPU_SKU_RE.search(title or "")
    return m.group(1) if m else None
