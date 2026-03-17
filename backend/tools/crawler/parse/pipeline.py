# backend/tools/crawler/parse/pipeline.py
"""Snapshot loading and listing-parse helpers for the crawl-parse CLI."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backend.services.crawler.parsers import get_listing_parser
from backend.services.crawler.sources import SourceId


@dataclass(frozen=True)
class ParsedSnapshot:
    snapshot_dir: Path
    meta: dict[str, Any]
    payload: list[dict[str, Any]]


def load_snapshot_payload(*, source: str, snapshot_dir: str) -> ParsedSnapshot:
    snap = Path(snapshot_dir).resolve()
    meta = json.loads((snap / "meta.json").read_text(encoding="utf-8"))
    html = (snap / "body.txt").read_text(encoding="utf-8", errors="replace")

    parser = get_listing_parser(SourceId(source))
    items = parser.parse_listings(html=html, page_url=meta.get("final_url") or meta["url"])
    payload = [item.__dict__ for item in items]

    return ParsedSnapshot(snapshot_dir=snap, meta=meta, payload=payload)
