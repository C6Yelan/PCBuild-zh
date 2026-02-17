# backend/services/crawler/staging/repo.py
from __future__ import annotations
import logging
import os
from backend.core.obs_events import log_loki_event

_PCBUILD_PIPELINE_LOGGER = logging.getLogger("pcbuild.pipeline")
_RUN_SOURCE_CACHE: dict[str, str] = {}

def _get_env() -> str:
    # 服務環境（低基數），若沒設就視為 prod
    return os.getenv("APP_ENV") or os.getenv("ENV") or "prod"

def _get_source(db, run_id) -> str:
    # 只在首次看到 run_id 時查一次 DB，避免每筆 gate_result 都查
    k = str(run_id)
    if k in _RUN_SOURCE_CACHE:
        return _RUN_SOURCE_CACHE[k]
    try:
        from backend.models.crawler_staging import CrawlerIngestRun
        r = db.get(CrawlerIngestRun, run_id)
        src = getattr(r, "source", None) or "unknown"
    except Exception:
        src = "unknown"
    _RUN_SOURCE_CACHE[k] = src
    return src


import hashlib
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from backend.models.crawler_staging import CrawlerIngestRun, CrawlerStgItem, CrawlerStgGateResult


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

    for it in items:
        _validate_item(it)

        item_key = _make_item_key(source, it)
        pk = (run_id, item_key)
        row = db.get(CrawlerStgItem, pk)

        if row is None:
            row = CrawlerStgItem(
                run_id=run_id,
                item_key=item_key,
                category=str(it["category"]),
                title=str(it["title"]),
                url=str(it["url"]),
                price=int(it["price"]),
                currency=str(it["currency"]),
                sku_hint=(str(it["sku_hint"]) if it.get("sku_hint") is not None else None),
                canonical_json=it,
            )
            db.add(row)
            inserted += 1
        else:
            row.category = str(it["category"])
            row.title = str(it["title"])
            row.url = str(it["url"])
            row.price = int(it["price"])
            row.currency = str(it["currency"])
            row.sku_hint = (str(it["sku_hint"]) if it.get("sku_hint") is not None else None)
            row.canonical_json = it
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
    if status not in ("pass", "fail"):
        raise ValueError("status 只能是 'pass' 或 'fail'")

    pk = (run_id, item_key, gate_name)
    row = db.get(CrawlerStgGateResult, pk)  # composite PK 可用 tuple 傳入
    prev_status = (row.status if row is not None else None)

    if status == "fail" and prev_status != "fail":
        log_loki_event(
            _PCBUILD_PIPELINE_LOGGER,
            level=logging.ERROR,
            event="gate_result",
            source=_get_source(db, run_id),
            stage="staging",
            gate_name=gate_name,
            env=_get_env(),
            run_id=str(run_id),
            item_key=item_key,
            status=status,
            detail_json=detail_json,
        )
    if row is None:
        db.add(
            CrawlerStgGateResult(
                run_id=run_id,
                item_key=item_key,
                gate_name=gate_name,
                status=status,
                detail_json=detail_json,
            )
        )
        db.flush()
        return (1, 0)

    row.status = status
    row.detail_json = detail_json
    db.flush()
    return (0, 1)


def _validate_item(it: dict[str, Any]) -> None:
    # 僅做最小必要欄位檢查，避免 DB constraint 才爆
    required = ("category", "title", "url", "price", "currency")
    missing = [k for k in required if it.get(k) in (None, "")]
    if missing:
        raise ValueError(f"staging item 缺必要欄位: {missing}")

    price = it.get("price")
    try:
        price_i = int(price)
    except Exception as e:
        raise ValueError(f"price 無法轉成 int: {price!r}") from e
    if price_i < 0:
        raise ValueError(f"price 不可為負數: {price_i}")


def _make_item_key(source: str, it: dict[str, Any]) -> str:
    # 穩定、可重算；避免因為 dict key 順序而變動
    seed = "|".join(
        [
            source,
            str(it.get("category") or ""),
            str(it.get("url") or ""),
            str(it.get("title") or ""),
            str(it.get("sku_hint") or ""),
        ]
    )
    return hashlib.sha1(seed.encode("utf-8")).hexdigest()
