# backend/tools/db/staging_write_runtime.py
"""Transactional staging write runtime for T7 helpers."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from backend.services.crawler.staging.repo import (
    StagingGateResultWrite,
    create_ingest_run,
    upsert_stg_gate_results,
    upsert_stg_items,
)
from backend.tools.db.staging_ingest_support.models import StagingCounts


def stage_items_and_gate_results(
    db: Session,
    *,
    source: str,
    note: str | None,
    run_id: UUID,
    items: list[dict[str, object]],
    gate_results: list[StagingGateResultWrite],
) -> StagingCounts:
    with db.begin():
        rid = create_ingest_run(db, source=source, note=note, run_id=run_id)
        inserted, updated = upsert_stg_items(db, run_id=rid, source=source, items=items)
        gate_inserted, gate_updated = upsert_stg_gate_results(
            db,
            run_id=rid,
            gate_results=gate_results,
        )

    return StagingCounts(
        item_inserted=int(inserted),
        item_updated=int(updated),
        gate_inserted=int(gate_inserted),
        gate_updated=int(gate_updated),
    )


__all__ = ["stage_items_and_gate_results"]
