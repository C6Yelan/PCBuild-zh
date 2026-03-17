# backend/tools/ops/crawler/incremental/incremental_fetch.py
"""Fetch façade for incremental crawler runs."""

from .incremental_fetch_runtime import collect_changed_parts
from .incremental_fetch_state import build_fetch_headers, record_fetch_state, utc_now

__all__ = [
    "build_fetch_headers",
    "collect_changed_parts",
    "record_fetch_state",
    "utc_now",
]
