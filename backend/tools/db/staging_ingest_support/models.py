# backend/tools/db/staging_ingest_support/models.py
"""Shared models for crawler staging-ingest runtimes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class StagingCounts:
    item_inserted: int
    item_updated: int
    gate_inserted: int
    gate_updated: int


@dataclass(frozen=True)
class StageIngestPayload:
    items: list[dict[str, Any]]
    gate_results: list[dict[str, Any]]


__all__ = ["StageIngestPayload", "StagingCounts"]
