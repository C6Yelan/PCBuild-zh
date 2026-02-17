from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session

from backend.db import SessionLocal
from backend.core.obs_events import log_loki_event
from backend.models.crawler_publication import CrawlerPublication, CrawlerPublicationPointer
from backend.models.crawler_staging import CrawlerIngestRun, CrawlerStgGateResult, CrawlerStgItem

_PIPELINE_LOGGER = logging.getLogger("pcbuild.pipeline")


def _select_pass_item_keys(db: Session, *, run_id: UUID) -> sa.Select:
    """
    與你既有的 gate 設計一致：
    - 以 crawler_stg_gate_result 依 item_key 分組
    - fail_cnt == 0 且 gate_cnt > 0 視為 pass item
    """
    fail_cnt = sa.func.sum(sa.case((CrawlerStgGateResult.status == "fail", 1), else_=0))
    gate_cnt = sa.func.count(sa.literal_column("*"))

    pass_keys_sq = (
        sa.select(CrawlerStgGateResult.item_key)
        .where(CrawlerStgGateResult.run_id == run_id)
        .group_by(CrawlerStgGateResult.item_key)
        .having(fail_cnt == 0)
        .having(gate_cnt > 0)
        .subquery()
    )
    return sa.select(pass_keys_sq.c.item_key)


def _calc_gate_stats(db: Session, *, run_id: UUID) -> dict[str, int]:
    gate_total = sa.func.count(sa.literal_column("*"))
    gate_pass = sa.func.sum(sa.case((CrawlerStgGateResult.status == "pass", 1), else_=0))
    gate_fail = sa.func.sum(sa.case((CrawlerStgGateResult.status == "fail", 1), else_=0))

    row = db.execute(
        sa.select(
            gate_total.label("gate_total"),
            gate_pass.label("gate_pass"),
            gate_fail.label("gate_fail"),
        ).where(CrawlerStgGateResult.run_id == run_id)
    ).one()

    return {
        "gate_total": int(row.gate_total or 0),
        "gate_pass": int(row.gate_pass or 0),
        "gate_fail": int(row.gate_fail or 0),
    }


def _calc_item_stats(db: Session, *, run_id: UUID) -> dict[str, int]:
    item_total = db.execute(
        sa.select(sa.func.count(sa.literal_column("*"))).where(CrawlerStgItem.run_id == run_id)
    ).scalar_one()

    pass_item_n = db.execute(
        sa.select(sa.func.count(sa.literal_column("*")))
        .select_from(_select_pass_item_keys(db, run_id=run_id).subquery())
    ).scalar_one()

    with_gate_sq = (
        sa.select(CrawlerStgGateResult.item_key)
        .where(CrawlerStgGateResult.run_id == run_id)
        .distinct()
        .subquery()
    )
    with_gate_n = db.execute(sa.select(sa.func.count(sa.literal_column("*"))).select_from(with_gate_sq)).scalar_one()
    no_gate_n = int(item_total) - int(with_gate_n)

    fail_cnt = sa.func.sum(sa.case((CrawlerStgGateResult.status == "fail", 1), else_=0))
    fail_keys_sq = (
        sa.select(CrawlerStgGateResult.item_key)
        .where(CrawlerStgGateResult.run_id == run_id)
        .group_by(CrawlerStgGateResult.item_key)
        .having(fail_cnt > 0)
        .subquery()
    )
    fail_item_n = db.execute(sa.select(sa.func.count(sa.literal_column("*"))).select_from(fail_keys_sq)).scalar_one()

    return {
        "item_total": int(item_total),
        "item_pass": int(pass_item_n),
        "item_fail": int(fail_item_n),
        "item_no_gate": int(no_gate_n),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="T9: publish a run as current release (pointer-based)")
    ap.add_argument("--run-id", required=True, help="crawler_ingest_run.run_id (UUID)")
    ap.add_argument("--env", default="prod", help="publication pointer env (default: prod)")
    ap.add_argument("--note", default=None, help="optional note stored in crawler_publication")
    ap.add_argument("--dry-run", action="store_true", help="validate & print stats only; no DB write")
    args = ap.parse_args()

    run_id = UUID(args.run_id)
    env = (args.env or "").strip()
    if not env:
        raise SystemExit("env cannot be empty")

    src = "unknown"
    db = SessionLocal()
    try:
        # Session.begin() 作為 context manager：確保交易一致性（commit/rollback）:contentReference[oaicite:1]{index=1}
        with db.begin():
            run = db.get(CrawlerIngestRun, run_id)
            if run is None:
                raise SystemExit(f"run_id not found: {run_id}")
            src = str(run.source)

            log_loki_event(
                _PIPELINE_LOGGER,
                event="t9_publish_started",
                source=src,
                stage="publish",
                env=env,
                run_id=str(run_id),
                dry_run=bool(args.dry_run),
            )

            gate_stats = _calc_gate_stats(db, run_id=run_id)
            item_stats = _calc_item_stats(db, run_id=run_id)

            # 發佈門檻：至少要有 1 個 pass item
            if item_stats["item_pass"] <= 0:
                raise SystemExit(f"no pass items; cannot publish. run_id={run_id}")

            stats = {
                "run_id": str(run_id),
                "source": str(run.source),
                "checked_at": datetime.now(timezone.utc).isoformat(),
                **gate_stats,
                **item_stats,
            }

            if args.dry_run:
                log_loki_event(
                    _PIPELINE_LOGGER,
                    event="t9_publish_finished",
                    source=src,
                    stage="publish",
                    env=env,
                    run_id=str(run_id),
                    dry_run=True,
                    published=False,
                    gate_total=gate_stats["gate_total"],
                    gate_pass=gate_stats["gate_pass"],
                    gate_fail=gate_stats["gate_fail"],
                    item_total=item_stats["item_total"],
                    item_pass=item_stats["item_pass"],
                    item_fail=item_stats["item_fail"],
                    item_no_gate=item_stats["item_no_gate"],
                )
                print(json.dumps({"ok": True, "dry_run": True, "env": env, "stats": stats}, ensure_ascii=False))
                return 0

            # upsert publication（PK: run_id）
            pub = db.get(CrawlerPublication, run_id)
            if pub is None:
                db.add(CrawlerPublication(run_id=run_id, note=args.note, stats_json=stats))
            else:
                if args.note is not None:
                    pub.note = args.note
                pub.stats_json = stats

            # upsert pointer（PK: env）
            ptr = db.get(CrawlerPublicationPointer, env)
            now = datetime.now(timezone.utc)
            if ptr is None:
                db.add(CrawlerPublicationPointer(env=env, run_id=run_id, updated_at=now))
            else:
                ptr.run_id = run_id
                ptr.updated_at = now

        log_loki_event(
            _PIPELINE_LOGGER,
            event="t9_publish_finished",
            source=src,
            stage="publish",
            env=env,
            run_id=str(run_id),
            dry_run=False,
            published=True,
            gate_total=stats["gate_total"],
            gate_pass=stats["gate_pass"],
            gate_fail=stats["gate_fail"],
            item_total=stats["item_total"],
            item_pass=stats["item_pass"],
            item_fail=stats["item_fail"],
            item_no_gate=stats["item_no_gate"],
        )

        print(json.dumps({"ok": True, "published": True, "env": env, "run_id": str(run_id)}, ensure_ascii=False))
        return 0
    except (Exception, SystemExit) as e:
        log_loki_event(
            _PIPELINE_LOGGER,
            level=logging.ERROR,
            event="t9_publish_failed",
            source=src,
            stage="publish",
            env=env,
            run_id=str(run_id),
            dry_run=bool(args.dry_run),
            error=str(e),
            exc_type=type(e).__name__,
        )
        raise
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
