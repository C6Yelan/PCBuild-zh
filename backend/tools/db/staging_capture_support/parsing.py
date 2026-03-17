# backend/tools/db/staging_capture_support/parsing.py
"""Stdout parsing helpers for crawl-parse and stage CLI wrappers."""

from __future__ import annotations

import json
from typing import Any

from backend.tools.crawler.io.artifact_io import extract_last_json_object


def load_pass_items(stdout_txt: str) -> list[dict[str, Any]]:
    if not stdout_txt.strip():
        return []

    parsed = json.loads(stdout_txt)
    if not isinstance(parsed, list):
        raise SystemExit("crawl_parse_snapshot stdout 不是 list JSON，無法入庫")
    return parsed


def parse_stage_summary(stdout_txt: str) -> tuple[dict[str, Any] | None, int, int, int, int, int]:
    result = extract_last_json_object(stdout_txt)
    item_inserted = int((result or {}).get("item_inserted") or 0)
    item_updated = int((result or {}).get("item_updated") or 0)
    gate_inserted = int((result or {}).get("gate_inserted") or 0)
    gate_updated = int((result or {}).get("gate_updated") or 0)
    raw_item_total = (result or {}).get("item_total")

    try:
        item_total = int(raw_item_total) if raw_item_total is not None else item_inserted + item_updated
    except (TypeError, ValueError):
        item_total = item_inserted + item_updated

    return result, item_total, item_inserted, item_updated, gate_inserted, gate_updated
