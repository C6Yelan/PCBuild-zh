# backend/tools/db/t8_merge_from_staging.py
from __future__ import annotations

import argparse
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session

from backend.db import SessionLocal
from backend.models.crawler_staging import CrawlerIngestRun, CrawlerStgItem, CrawlerStgGateResult
from backend.services.catalog.repo import (
    upsert_source,
    upsert_product,
    upsert_price_snapshot,
    upsert_spec_key,
    upsert_product_spec,
    normalize_value_text,
)


def _select_pass_items(db: Session, *, run_id: UUID) -> list[CrawlerStgItem]:
    # 規則：該 item 在此 run 中「沒有任何 fail gate」，且至少有 1 筆 gate_result
    fail_cnt = sa.func.sum(sa.case((CrawlerStgGateResult.status == "fail", 1), else_=0))
    gate_cnt = sa.func.count(sa.literal_column("*"))

    ok_keys_sq = (
        sa.select(CrawlerStgGateResult.item_key)
        .where(CrawlerStgGateResult.run_id == run_id)
        .group_by(CrawlerStgGateResult.item_key)
        .having(fail_cnt == 0)
        .having(gate_cnt > 0)
        .subquery()
    )

    return list(
        db.execute(
            sa.select(CrawlerStgItem)
            .where(CrawlerStgItem.run_id == run_id)
            .where(CrawlerStgItem.item_key.in_(sa.select(ok_keys_sq.c.item_key)))
            .order_by(CrawlerStgItem.item_key)
        ).scalars()
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True, help="crawler_ingest_run.run_id (UUID)")
    args = ap.parse_args()

    run_id = UUID(args.run_id)

    db = SessionLocal()
    try:
        with db.begin():
            run = db.get(CrawlerIngestRun, run_id)
            if run is None:
                raise SystemExit(f"run_id not found: {run_id}")

            source_code = run.source
            source_id = upsert_source(db, code=source_code, name=source_code)

            items = _select_pass_items(db, run_id=run_id)

            product_n = 0
            price_n = 0
            spec_n = 0

            for it in items:
                pid = upsert_product(
                    db,
                    source_id=source_id,
                    source_item_key=it.item_key,
                    category=it.category,
                    title=it.title,
                    url=it.url,
                    sku_hint=it.sku_hint,
                    run_id=run_id,
                )
                product_n += 1

                upsert_price_snapshot(
                    db,
                    product_id=pid,
                    run_id=run_id,
                    price=int(it.price),
                    currency=str(it.currency),
                )
                price_n += 1

                extra = (it.canonical_json or {}).get("extra")
                if isinstance(extra, dict):
                    for k, v in extra.items():
                        key_id = upsert_spec_key(db, key=str(k))
                        upsert_product_spec(
                            db,
                            product_id=pid,
                            spec_key_id=key_id,
                            value_text=normalize_value_text(v),
                            unit=None,
                        )
                        spec_n += 1

        print(
            f"T8 merge OK: run_id={run_id} items(pass)={len(items)} "
            f"product_upsert={product_n} price_upsert={price_n} spec_upsert={spec_n}"
        )
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
