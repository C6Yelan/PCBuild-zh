# backend/tools/db/staging_ingest.py
"""ORM staging helpers for ingest runs and gate-result rows."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from backend.services.crawler.staging.conventions import make_item_key
from backend.services.crawler.staging.repo import (
    create_ingest_run,
    upsert_stg_gate_result,
    upsert_stg_items,
)


@dataclass(frozen=True)
class StagingCounts:
    item_inserted: int
    item_updated: int
    gate_inserted: int
    gate_updated: int


def _resolve_t5_status(*, crawl_rc: int, t5_summary: Any) -> str:
    status = "pass"
    if crawl_rc != 0:
        status = "fail"
    if isinstance(t5_summary, dict) and int(t5_summary.get("non_match") or 0) > 0:
        status = "fail"
    return status


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
    with db.begin():
        rid = create_ingest_run(db, source=source, note=note, run_id=run_id)
        inserted, updated = upsert_stg_items(db, run_id=rid, source=source, items=items)

        gate_inserted = 0
        gate_updated = 0
        snapshot_name = str(Path(snapshot_dir).name)
        t5_status = _resolve_t5_status(crawl_rc=crawl_rc, t5_summary=t5_summary)

        for item in items:
            item_key = make_item_key(source, item)

            ins, upd = upsert_stg_gate_result(
                db,
                run_id=rid,
                item_key=item_key,
                gate_name="t4_dq",
                status="pass",
                detail_json={
                    "artifact_dir": str(artifact_dir),
                    "snapshot_dir": snapshot_name,
                    "dq_report": dq_meta,
                    "dq_report_keys": list(dq_report.keys()) if isinstance(dq_report, dict) else None,
                },
            )
            gate_inserted += ins
            gate_updated += upd

            if enable_t5:
                ins2, upd2 = upsert_stg_gate_result(
                    db,
                    run_id=rid,
                    item_key=item_key,
                    gate_name="t5_link",
                    status=t5_status,
                    detail_json={
                        "artifact_dir": str(artifact_dir),
                        "snapshot_dir": snapshot_name,
                        "t5_summary": t5_meta,
                        "t5_summary_keys": list(t5_summary.keys()) if isinstance(t5_summary, dict) else None,
                    },
                )
                gate_inserted += ins2
                gate_updated += upd2

    return StagingCounts(
        item_inserted=int(inserted),
        item_updated=int(updated),
        gate_inserted=int(gate_inserted),
        gate_updated=int(gate_updated),
    )
