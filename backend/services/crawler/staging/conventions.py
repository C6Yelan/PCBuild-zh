"""Shared conventions for crawler staging identity and logging context."""
# backend/services/crawler/staging/conventions.py

from __future__ import annotations

import hashlib
import os
from typing import Any


def get_crawler_env() -> str:
    return os.getenv("APP_ENV") or os.getenv("ENV") or "prod"


def make_item_key(source: str, item: dict[str, Any]) -> str:
    seed = "|".join(
        [
            source,
            str(item.get("category") or ""),
            str(item.get("url") or ""),
            str(item.get("title") or ""),
            str(item.get("sku_hint") or ""),
        ]
    )
    return hashlib.sha1(seed.encode("utf-8")).hexdigest()
