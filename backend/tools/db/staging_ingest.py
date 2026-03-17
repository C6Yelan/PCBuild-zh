# backend/tools/db/staging_ingest.py
"""Thin public facade for T7 staging ingest runtime helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from backend.tools.db.staging_gate_writes import (
    build_json_gate_result_writes,
    build_snapshot_gate_result_writes,
)
from backend.tools.db.staging_ingest_support.models import StageIngestPayload, StagingCounts
from backend.tools.db.staging_ingest_support.payload import load_stage_ingest_payload
from backend.tools.db.staging_write_runtime import stage_items_and_gate_results


def stage_json_payload(
    db: Session,
    *,
    source: str,
    note: str | None,
    run_id: UUID,
    payload: StageIngestPayload,
) -> StagingCounts:
    gate_results = build_json_gate_result_writes(
        source=source,
        items=payload.items,
        gate_results=payload.gate_results,
    )
    return stage_items_and_gate_results(
        db,
        source=source,
        note=note,
        run_id=run_id,
        items=payload.items,
        gate_results=gate_results,
    )


def stage_snapshot_items(
    db: Session,
    *,
    source: str,
    note: str | None,
    run_id: UUID,
    snapshot_dir: str,
    artifact_dir: Path,
    items: list[dict[str, Any]],
    crawl_rc: int,
    enable_t5: bool,
    dq_report: Any,
    dq_meta: dict[str, Any] | None,
    t5_summary: Any,
    t5_meta: dict[str, Any] | None,
) -> StagingCounts:
    gate_results = build_snapshot_gate_result_writes(
        source=source,
        snapshot_dir=snapshot_dir,
        artifact_dir=artifact_dir,
        items=items,
        crawl_rc=crawl_rc,
        enable_t5=enable_t5,
        dq_report=dq_report,
        dq_meta=dq_meta,
        t5_summary=t5_summary,
        t5_meta=t5_meta,
    )
    return stage_items_and_gate_results(
        db,
        source=source,
        note=note,
        run_id=run_id,
        items=items,
        gate_results=gate_results,
    )


__all__ = [
    "StageIngestPayload",
    "StagingCounts",
    "load_stage_ingest_payload",
    "stage_items_and_gate_results",
    "stage_json_payload",
    "stage_snapshot_items",
]
