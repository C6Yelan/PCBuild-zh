# backend/tools/ops/crawler/incremental/incremental_parsing.py
"""Stdout parsing helpers for incremental ops subcommands."""

from __future__ import annotations

import json
import re
from typing import Any

from backend.tools.crawler.io.artifact_io import extract_last_json_object


_T8_COUNTS_RE = re.compile(
    r"items\(pass\)=(?P<items>\d+)\s+product_upsert=(?P<product>\d+)\s+price_upsert=(?P<price>\d+)\s+spec_upsert=(?P<spec>\d+)"
)


def extract_json_array(text: str) -> list[dict[str, Any]] | None:
    stripped = text.strip()
    if not stripped:
        return []

    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
    except json.JSONDecodeError:
        pass

    start = stripped.find("[")
    end = stripped.rfind("]")
    if start >= 0 and end > start:
        fragment = stripped[start : end + 1]
        try:
            parsed = json.loads(fragment)
            if isinstance(parsed, list):
                return [item for item in parsed if isinstance(item, dict)]
        except json.JSONDecodeError:
            return None
    return None


def parse_t8_counts(text: str) -> dict[str, int] | None:
    match = _T8_COUNTS_RE.search(text)
    if not match:
        return None
    return {
        "items_pass": int(match.group("items")),
        "product_upsert": int(match.group("product")),
        "price_upsert": int(match.group("price")),
        "spec_upsert": int(match.group("spec")),
    }
