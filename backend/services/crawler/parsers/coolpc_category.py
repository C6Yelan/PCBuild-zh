# backend/services/crawler/parsers/coolpc_category.py
from __future__ import annotations

from urllib.parse import parse_qs, urlparse

_COOLPC_IGRP_CATEGORY: dict[str, str] = {
    "4": "CPU",
    "5": "MB",
    "6": "RAM",
    "7": "SSD",
    "8": "HDD",
    "10": "COOLER",
    "11": "LIQUID_COOLING",
    "14": "CASE",
    "15": "PSU",
    "16": "CASE_FAN",
    "27": "EXPANSION_CARD",
    "12": "GPU",
}


def infer_category_from_page_url(page_url: str) -> str | None:
    try:
        q = parse_qs(urlparse(page_url).query)
        igrp = (q.get("IGrp") or [None])[0]
        if igrp and igrp in _COOLPC_IGRP_CATEGORY:
            return _COOLPC_IGRP_CATEGORY[igrp]
    except Exception:
        pass
    return None
