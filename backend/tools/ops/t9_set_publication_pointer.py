# backend/tools/ops/t9_set_publication_pointer.py
from __future__ import annotations

import argparse
import json
import logging
import os
import time
from datetime import datetime, timezone
from uuid import UUID

from backend.db import SessionLocal
from backend.core.obs_events import ensure_cli_logging, log_loki_event
from backend.models.crawler_publication import CrawlerPublication, CrawlerPublicationPointer

_PIPELINE_LOGGER = logging.getLogger("pcbuild.pipeline")


def main() -> int:
    ap = argparse.ArgumentParser(description="T9: set publication pointer (env -> published run_id)")
    ap.add_argument("--env", default="prod", help="pointer env (default: prod)")
    ap.add_argument("--run-id", required=True, help="target published run_id (UUID)")
    ap.add_argument("--dry-run", action="store_true", help="print changes only; no DB write")
    args = ap.parse_args()

    env = (args.env or "").strip()
    if not env:
        raise SystemExit("env cannot be empty")

    run_id = UUID(args.run_id)
    ensure_cli_logging(logger=_PIPELINE_LOGGER)
    app_git_sha = (os.getenv("APP_GIT_SHA") or "unknown").strip() or "unknown"
    t0 = time.monotonic()

    src = "unknown"
    before: str | None = None
    db = SessionLocal()
    try:
        log_loki_event(
            _PIPELINE_LOGGER,
            event="t9_pointer_set_started",
            source=src,
            stage="publish",
            env=env,
            run_id=str(run_id),
            dry_run=bool(args.dry_run),
            app_git_sha=app_git_sha,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        with db.begin():
            pub = db.get(CrawlerPublication, run_id)
            if pub is None:
                raise SystemExit(f"run_id is not published yet: {run_id}")
            if isinstance(pub.stats_json, dict):
                src = str(pub.stats_json.get("source") or "unknown")

            ptr = db.get(CrawlerPublicationPointer, env)
            before = None if ptr is None else str(ptr.run_id)

            if args.dry_run:
                changed = before != str(run_id)
                log_loki_event(
                    _PIPELINE_LOGGER,
                    event="t9_pointer_set_finished",
                    source=src,
                    stage="publish",
                    env=env,
                    run_id=str(run_id),
                    dry_run=True,
                    changed=changed,
                    before_run_id=before,
                    after_run_id=str(run_id),
                    app_git_sha=app_git_sha,
                    elapsed_ms=int((time.monotonic() - t0) * 1000),
                    ended_at=datetime.now(timezone.utc).isoformat(),
                )
                print(
                    json.dumps(
                        {
                            "ok": True,
                            "dry_run": True,
                            "env": env,
                            "before_run_id": before,
                            "after_run_id": str(run_id),
                        },
                        ensure_ascii=False,
                    )
                )
                return 0

            now = datetime.now(timezone.utc)
            if ptr is None:
                db.add(CrawlerPublicationPointer(env=env, run_id=run_id, updated_at=now))
                pointer_action = "created"
            else:
                ptr.run_id = run_id
                ptr.updated_at = now
                pointer_action = "updated"

        changed = before != str(run_id)
        log_loki_event(
            _PIPELINE_LOGGER,
            event="t9_pointer_set_finished",
            source=src,
            stage="publish",
            env=env,
            run_id=str(run_id),
            dry_run=False,
            changed=changed,
            before_run_id=before,
            after_run_id=str(run_id),
            pointer_action=pointer_action,
            app_git_sha=app_git_sha,
            elapsed_ms=int((time.monotonic() - t0) * 1000),
            ended_at=datetime.now(timezone.utc).isoformat(),
        )

        print(json.dumps({"ok": True, "env": env, "run_id": str(run_id)}, ensure_ascii=False))
        return 0
    except (Exception, SystemExit) as e:
        log_loki_event(
            _PIPELINE_LOGGER,
            level=logging.ERROR,
            event="t9_pointer_set_failed",
            source=src,
            stage="publish",
            env=env,
            run_id=str(run_id),
            dry_run=bool(args.dry_run),
            before_run_id=before,
            app_git_sha=app_git_sha,
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
