# backend/tools/ops/t9_db_retention.py
from __future__ import annotations

"""T9 DB retention cleanup tool.

Usage:
  python -m backend.tools.ops.t9_db_retention --dry-run
  python -m backend.tools.ops.t9_db_retention --confirm
  python -m backend.tools.ops.t9_db_retention --confirm --vacuum
"""

import argparse
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import TextClause

from backend.db import SessionLocal, engine


COUNT_UNPUBLISHED_RUN_SQL = sa.text(
    """
    SELECT count(*) AS cnt, min(r.created_at) AS oldest_created_at
    FROM crawler_ingest_run r
    WHERE r.created_at < :cutoff
      AND NOT EXISTS (
        SELECT 1 FROM crawler_publication p WHERE p.run_id = r.run_id
      )
    """
)

COUNT_PUBLISHED_STG_ITEM_SQL = sa.text(
    """
    SELECT count(*) AS cnt, min(i.created_at) AS oldest_created_at
    FROM crawler_stg_item i
    JOIN crawler_publication p ON p.run_id = i.run_id
    WHERE i.created_at < :cutoff
    """
)

COUNT_PUBLISHED_GATE_RESULT_SQL = sa.text(
    """
    SELECT count(*) AS cnt, min(g.created_at) AS oldest_created_at
    FROM crawler_stg_gate_result g
    JOIN crawler_publication p ON p.run_id = g.run_id
    WHERE g.created_at < :cutoff
    """
)

DELETE_UNPUBLISHED_RUN_BATCH_SQL = sa.text(
    """
    WITH doomed AS (
      SELECT r.run_id
      FROM crawler_ingest_run r
      WHERE r.created_at < :cutoff
        AND NOT EXISTS (
          SELECT 1 FROM crawler_publication p WHERE p.run_id = r.run_id
        )
      ORDER BY r.created_at
      LIMIT :batch
    )
    DELETE FROM crawler_ingest_run r
    USING doomed d
    WHERE r.run_id = d.run_id
    RETURNING r.run_id
    """
)

DELETE_PUBLISHED_STG_ITEM_BATCH_SQL = sa.text(
    """
    WITH doomed AS (
      SELECT i.run_id, i.item_key
      FROM crawler_stg_item i
      JOIN crawler_publication p ON p.run_id = i.run_id
      WHERE i.created_at < :cutoff
      ORDER BY i.created_at
      LIMIT :batch
    )
    DELETE FROM crawler_stg_item i
    USING doomed d
    WHERE i.run_id = d.run_id AND i.item_key = d.item_key
    RETURNING i.run_id
    """
)

VACUUM_STMTS: tuple[tuple[str, TextClause], ...] = (
    ("crawler_ingest_run", sa.text("VACUUM (ANALYZE) crawler_ingest_run")),
    ("crawler_stg_item", sa.text("VACUUM (ANALYZE) crawler_stg_item")),
    ("crawler_stg_gate_result", sa.text("VACUUM (ANALYZE) crawler_stg_gate_result")),
)


@dataclass(frozen=True)
class CountStat:
    count: int
    oldest_created_at: datetime | None


def _non_negative_int(value: str) -> int:
    n = int(value)
    if n < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return n


def _positive_int(value: str) -> int:
    n = int(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return n


def _format_dt(value: datetime | None) -> str:
    return value.isoformat() if value is not None else "n/a"


def _run_count_query(db: Session, stmt: TextClause, *, cutoff: datetime) -> CountStat:
    row = db.execute(stmt, {"cutoff": cutoff}).one()
    return CountStat(
        count=int(row[0] or 0),
        oldest_created_at=row[1],
    )


def _collect_stats(
    db: Session,
    *,
    cutoff_unpublished: datetime,
    cutoff_published_staging: datetime,
) -> tuple[CountStat, CountStat, CountStat]:
    unpublished_runs = _run_count_query(db, COUNT_UNPUBLISHED_RUN_SQL, cutoff=cutoff_unpublished)
    published_stg_items = _run_count_query(
        db,
        COUNT_PUBLISHED_STG_ITEM_SQL,
        cutoff=cutoff_published_staging,
    )
    published_gate_results = _run_count_query(
        db,
        COUNT_PUBLISHED_GATE_RESULT_SQL,
        cutoff=cutoff_published_staging,
    )
    return unpublished_runs, published_stg_items, published_gate_results


def _print_cutoff_summary(
    *,
    now_utc: datetime,
    cutoff_unpublished: datetime,
    cutoff_published_staging: datetime,
    unpublished_days: int,
    published_staging_days: int,
) -> None:
    print("=== T9 DB retention ===")
    print(f"now_utc: {now_utc.isoformat()}")
    print(
        "cutoff_unpublished: "
        f"{cutoff_unpublished.isoformat()} (unpublished-days={unpublished_days})"
    )
    print(
        "cutoff_published_staging: "
        f"{cutoff_published_staging.isoformat()} "
        f"(published-staging-days={published_staging_days})"
    )


def _print_stats_summary(
    *,
    unpublished_runs: CountStat,
    published_stg_items: CountStat,
    published_gate_results: CountStat,
) -> None:
    print("overdue_unpublished_ingest_run:")
    print(f"  count={unpublished_runs.count} oldest_created_at={_format_dt(unpublished_runs.oldest_created_at)}")

    print("overdue_published_stg_item:")
    print(f"  count={published_stg_items.count} oldest_created_at={_format_dt(published_stg_items.oldest_created_at)}")

    print("overdue_published_stg_gate_result:")
    print(
        f"  count={published_gate_results.count} "
        f"oldest_created_at={_format_dt(published_gate_results.oldest_created_at)}"
    )


def _delete_in_batches(
    db: Session,
    *,
    label: str,
    stmt: TextClause,
    cutoff: datetime,
    batch_size: int,
    max_batches: int,
) -> tuple[int, int]:
    total_deleted = 0
    batches = 0

    while True:
        if max_batches > 0 and batches >= max_batches:
            print(f"[{label}] reached max-batches={max_batches}, stop.")
            break

        t0 = time.monotonic()
        rows = db.execute(
            stmt,
            {
                "cutoff": cutoff,
                "batch": batch_size,
            },
        ).fetchall()
        deleted = len(rows)

        if deleted == 0:
            db.rollback()
            break

        db.commit()
        batches += 1
        total_deleted += deleted

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        print(f"[{label}] batch={batches} deleted={deleted} total_deleted={total_deleted} elapsed_ms={elapsed_ms}")

    return total_deleted, batches


def _run_vacuum() -> None:
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        for table, stmt in VACUUM_STMTS:
            conn.execute(stmt)
            print(f"vacuum_done: {table}")


def main() -> int:
    ap = argparse.ArgumentParser(description="T9: DB retention cleanup for crawler staging data")
    ap.add_argument("--unpublished-days", type=_non_negative_int, default=30)
    ap.add_argument("--published-staging-days", type=_non_negative_int, default=180)
    ap.add_argument("--batch-size", type=_positive_int, default=5000)
    ap.add_argument("--max-batches", type=_non_negative_int, default=0)
    ap.add_argument("--vacuum", action="store_true", help="run VACUUM (ANALYZE) after deletion")
    ap.add_argument("--dry-run", action="store_true", help="print counts only; no delete")
    ap.add_argument("--confirm", action="store_true", help="confirm actual deletion")
    args = ap.parse_args()

    if args.dry_run and args.confirm:
        print("error: --dry-run and --confirm cannot be used together", file=sys.stderr)
        return 2
    if not args.dry_run and not args.confirm:
        print("error: deletion is blocked without --confirm (or use --dry-run)", file=sys.stderr)
        return 2

    now_utc = datetime.now(timezone.utc)
    cutoff_unpublished = now_utc - timedelta(days=args.unpublished_days)
    cutoff_published_staging = now_utc - timedelta(days=args.published_staging_days)

    t0_total = time.monotonic()

    with SessionLocal() as db:
        _print_cutoff_summary(
            now_utc=now_utc,
            cutoff_unpublished=cutoff_unpublished,
            cutoff_published_staging=cutoff_published_staging,
            unpublished_days=args.unpublished_days,
            published_staging_days=args.published_staging_days,
        )

        pre_unpub, pre_stg, pre_gate = _collect_stats(
            db,
            cutoff_unpublished=cutoff_unpublished,
            cutoff_published_staging=cutoff_published_staging,
        )
        print("precheck_stats:")
        _print_stats_summary(
            unpublished_runs=pre_unpub,
            published_stg_items=pre_stg,
            published_gate_results=pre_gate,
        )

        if args.dry_run:
            elapsed_ms = int((time.monotonic() - t0_total) * 1000)
            print(f"mode: dry-run elapsed_ms={elapsed_ms}")
            return 0

        deleted_unpub, batch_unpub = _delete_in_batches(
            db,
            label="delete_unpublished_ingest_run",
            stmt=DELETE_UNPUBLISHED_RUN_BATCH_SQL,
            cutoff=cutoff_unpublished,
            batch_size=args.batch_size,
            max_batches=args.max_batches,
        )

        deleted_stg, batch_stg = _delete_in_batches(
            db,
            label="delete_published_stg_item",
            stmt=DELETE_PUBLISHED_STG_ITEM_BATCH_SQL,
            cutoff=cutoff_published_staging,
            batch_size=args.batch_size,
            max_batches=args.max_batches,
        )

        post_unpub, post_stg, post_gate = _collect_stats(
            db,
            cutoff_unpublished=cutoff_unpublished,
            cutoff_published_staging=cutoff_published_staging,
        )

    if args.vacuum:
        _run_vacuum()

    elapsed_ms = int((time.monotonic() - t0_total) * 1000)
    print("delete_summary:")
    print(
        "  delete_unpublished_ingest_run: "
        f"batches={batch_unpub} deleted={deleted_unpub}"
    )
    print(
        "  delete_published_stg_item: "
        f"batches={batch_stg} deleted={deleted_stg}"
    )
    print("postcheck_stats:")
    _print_stats_summary(
        unpublished_runs=post_unpub,
        published_stg_items=post_stg,
        published_gate_results=post_gate,
    )
    print(f"mode: confirm elapsed_ms={elapsed_ms}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
