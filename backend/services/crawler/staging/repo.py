# backend/services/crawler/staging/repo.py
"""Crawler staging ORM repo surface.

Keep this module as the stable persistence entrypoint for t7 callers while
item payloads, row mapping, and event logging live in sibling helpers.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from backend.models.crawler_staging import CrawlerIngestRun, CrawlerStgGateResult, CrawlerStgItem
from backend.services.crawler.staging.staging_events import (
    log_gate_result_failure_transition,
)
from backend.services.crawler.staging.staging_payloads import (
    build_staging_gate_payload,
    build_staging_item_payload,
)
from backend.services.crawler.staging.staging_rows import (
    apply_staging_gate_payload,
    apply_staging_item_payload,
    create_staging_gate_result_row,
    create_staging_item_row,
)

_PCBUILD_PIPELINE_LOGGER = logging.getLogger("pcbuild.pipeline")


def create_ingest_run(
    db: Session,
    *,
    source: str,
    note: str | None = None,
    run_id: UUID | None = None,
) -> UUID:
    """
    建立一筆 crawler_ingest_run（不在此 commit，由呼叫端負責交易/commit）。
    若 run_id 已存在，會直接回傳該 run_id（並維持原資料，不強制覆寫 source/note）。
    """
    rid = run_id or uuid4()

    existing = db.get(CrawlerIngestRun, rid)
    if existing is not None:
        return rid

    run = CrawlerIngestRun(run_id=rid, source=source, note=note)
    db.add(run)
    db.flush()  # 確保在同一交易內可被後續 FK 參照
    return rid


def upsert_stg_items(
    db: Session,
    *,
    run_id: UUID,
    source: str,
    items: list[dict[str, Any]],
) -> tuple[int, int]:
    """
    將 canonical items upsert 到 crawler_stg_item。
    - 完全使用 ORM：先 db.get() 看是否存在，再更新或新增。
    - 回傳 (inserted, updated)
    """
    inserted = 0
    updated = 0

    for item in items:
        payload = build_staging_item_payload(source=source, item=item)
        pk = (run_id, payload.item_key)
        row = db.get(CrawlerStgItem, pk)

        if row is None:
            db.add(
                create_staging_item_row(
                    run_id=run_id,
                    payload=payload,
                )
            )
            inserted += 1
        else:
            apply_staging_item_payload(row, payload=payload)
            updated += 1

    db.flush()
    return inserted, updated


def upsert_stg_gate_result(
    db: Session,
    *,
    run_id: UUID,
    item_key: str,
    gate_name: str,
    status: str,
    detail_json: dict[str, Any] | None = None,
) -> tuple[int, int]:
    """
    Upsert 一筆 gate result（PK: run_id + item_key + gate_name）
    回傳 (inserted, updated)
    """
    payload = build_staging_gate_payload(
        gate_name=gate_name,
        status=status,
        detail_json=detail_json,
    )
    pk = (run_id, item_key, payload.gate_name)
    row = db.get(CrawlerStgGateResult, pk)  # composite PK 可用 tuple 傳入
    prev_status = (row.status if row is not None else None)

    if payload.status == "fail" and prev_status != "fail":
        log_gate_result_failure_transition(
            logger=_PCBUILD_PIPELINE_LOGGER,
            db=db,
            run_id=run_id,
            item_key=item_key,
            gate_name=payload.gate_name,
            status=payload.status,
            detail_json=payload.detail_json,
        )
    if row is None:
        db.add(
            create_staging_gate_result_row(
                run_id=run_id,
                item_key=item_key,
                payload=payload,
            )
        )
        db.flush()
        return (1, 0)

    apply_staging_gate_payload(row, payload=payload)
    db.flush()
    return (0, 1)
