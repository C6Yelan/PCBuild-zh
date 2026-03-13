# backend/tools/ops/crawler/list_publications_cli.py
from __future__ import annotations

import argparse
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

import sqlalchemy as sa

from backend.db import SessionLocal
from backend.core.obs_events import ensure_cli_logging, log_loki_event
from backend.models.crawler_publication import CrawlerPublication, CrawlerPublicationPointer

_PIPELINE_LOGGER = logging.getLogger("pcbuild.pipeline")


def _stats_summary(stats: dict[str, Any] | None) -> dict[str, Any]:
    s = stats or {}
    keys = [
        "source",
        "checked_at",
        "gate_total",
        "gate_pass",
        "gate_fail",
        "item_total",
        "item_pass",
        "item_fail",
        "item_no_gate",
    ]
    return {k: s.get(k) for k in keys if k in s}


def main() -> int:
    ap = argparse.ArgumentParser(description="T9: list publications & pointers")
    ap.add_argument("--limit", type=int, default=20, help="number of publications to show (default: 20)")
    ap.add_argument("--env", default=None, help="filter pointer env (default: all)")
    ap.add_argument("--with-stats-json", action="store_true", help="include full stats_json (may be large)")
    args = ap.parse_args()

    limit = max(1, min(int(args.limit), 200))
    ensure_cli_logging(logger=_PIPELINE_LOGGER)
    app_git_sha = (os.getenv("APP_GIT_SHA") or "unknown").strip() or "unknown"
    env_value = (args.env or "").strip() or None
    env_filter = env_value or "all"
    t0 = time.monotonic()

    db = SessionLocal()
    try:
        log_loki_event(
            _PIPELINE_LOGGER,
            event="t9_publication_list_started",
            source="unknown",
            stage="publish",
            env=env_value,
            app_git_sha=app_git_sha,
            limit=limit,
            env_filter=env_filter,
            with_stats_json=bool(args.with_stats_json),
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        # pointers
        ptr_stmt = sa.select(CrawlerPublicationPointer)
        if env_value:
            ptr_stmt = ptr_stmt.where(CrawlerPublicationPointer.env == env_value)

        ptrs = db.execute(ptr_stmt).scalars().all()
        pointers = {
            p.env: {"run_id": str(p.run_id), "updated_at": p.updated_at.isoformat()}
            for p in ptrs
        }

        # publications (latest first)
        pubs = (
            db.execute(
                sa.select(CrawlerPublication)
                .order_by(CrawlerPublication.published_at.desc())
                .limit(limit)
            )
            .scalars()
            .all()
        )

        out_pubs: list[dict[str, Any]] = []
        for pub in pubs:
            d: dict[str, Any] = {
                "run_id": str(pub.run_id),
                "published_at": pub.published_at.isoformat(),
                "note": pub.note,
            }
            if args.with_stats_json:
                d["stats_json"] = pub.stats_json
            else:
                d["stats"] = _stats_summary(pub.stats_json)
            out_pubs.append(d)

        log_loki_event(
            _PIPELINE_LOGGER,
            event="t9_publication_list_finished",
            source="unknown",
            stage="publish",
            env=env_value,
            app_git_sha=app_git_sha,
            limit=limit,
            env_filter=env_filter,
            with_stats_json=bool(args.with_stats_json),
            pointer_count=len(pointers),
            publication_count=len(out_pubs),
            elapsed_ms=int((time.monotonic() - t0) * 1000),
            ended_at=datetime.now(timezone.utc).isoformat(),
        )

        print(
            json.dumps(
                {"ok": True, "pointers": pointers, "publications": out_pubs},
                ensure_ascii=False,
            )
        )
        return 0
    except (Exception, SystemExit) as e:
        log_loki_event(
            _PIPELINE_LOGGER,
            level=logging.ERROR,
            event="t9_publication_list_failed",
            source="unknown",
            stage="publish",
            env=env_value,
            app_git_sha=app_git_sha,
            limit=limit,
            env_filter=env_filter,
            with_stats_json=bool(args.with_stats_json),
            error=str(e),
            exc_type=type(e).__name__,
            elapsed_ms=int((time.monotonic() - t0) * 1000),
            ended_at=datetime.now(timezone.utc).isoformat(),
        )
        raise
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
