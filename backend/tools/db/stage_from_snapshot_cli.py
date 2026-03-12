# backend/tools/db/stage_from_snapshot_cli.py
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from backend.core.obs_events import ensure_cli_logging, log_loki_event
from backend.db import SessionLocal
from backend.services.crawler.staging.conventions import get_app_git_sha, get_crawler_env
from backend.tools.db.staging_artifacts import (
    load_gate_artifacts,
    resolve_artifact_paths,
)
from backend.tools.db.staging_capture import (
    build_crawl_parse_argv,
    load_pass_items,
    run_crawl_parse,
)
from backend.tools.db.staging_ingest import stage_snapshot_items

_PIPELINE_LOGGER = logging.getLogger("pcbuild.pipeline")


def main() -> int:
    ap = argparse.ArgumentParser(description="T7: stage from snapshot-dir (run crawl_parse_snapshot then ORM ingest)")
    ap.add_argument("--source", required=True)
    ap.add_argument("--snapshot-dir", required=True)
    ap.add_argument("--note", default=None)
    ap.add_argument("--run-id", default=None)
    ap.add_argument(
        "--artifact-dir",
        default=None,
        help="(optional) output dir for DQ/T5 artifacts; default temp/t7/<run_id>",
    )

    # 是否啟用 T5：crawl_parse_snapshot 是「有 t5-outdir 才會跑」
    ap.add_argument("--enable-t5", action="store_true")
    ap.add_argument("--t5-limit", default=0, type=int)
    ap.add_argument("--t5-min-interval-ms", default=1500, type=int)
    ap.add_argument("--t5-timeout-s", default=10.0, type=float)
    ap.add_argument("--t5-max-redirects", default=5, type=int)
    ap.add_argument("--t5-max-bytes", default=4194304, type=int)
    ap.add_argument("--t5-block-pattern", action="append", default=[])

    args = ap.parse_args()

    # Keep this module path stable for existing pipeline callers; detailed staging steps live in sibling helpers.
    run_id: UUID = UUID(args.run_id) if args.run_id else uuid4()
    ensure_cli_logging(logger=_PIPELINE_LOGGER)
    src = str(args.source)
    app_git_sha = get_app_git_sha()
    artifact_dir = None
    t0 = time.monotonic()

    # run metadata: started
    log_loki_event(
        _PIPELINE_LOGGER,
        event="t7_stage_started",
        source=src,
        stage="stage",
        env=get_crawler_env(),
        run_id=str(run_id),
        app_git_sha=app_git_sha,
        snapshot_dir=str(args.snapshot_dir),
        snapshot_name=str(Path(args.snapshot_dir).name),
        enable_t5=bool(args.enable_t5),
        t5_limit=int(args.t5_limit),
        t5_min_interval_ms=int(args.t5_min_interval_ms),
        t5_timeout_s=float(args.t5_timeout_s),
        t5_max_redirects=int(args.t5_max_redirects),
        t5_max_bytes=int(args.t5_max_bytes),
        started_at=datetime.now(timezone.utc).isoformat(),
    )

    try:
        artifact_paths = resolve_artifact_paths(
            artifact_dir=args.artifact_dir,
            run_id=run_id,
            enable_t5=bool(args.enable_t5),
        )
        base_outdir = artifact_paths.base_outdir
        artifact_dir = str(base_outdir)

        crawl_argv = build_crawl_parse_argv(
            source=args.source,
            snapshot_dir=args.snapshot_dir,
            run_id=run_id,
            dq_outdir=artifact_paths.dq_outdir,
            t5_outdir=artifact_paths.t5_outdir,
            t5_limit=int(args.t5_limit),
            t5_min_interval_ms=int(args.t5_min_interval_ms),
            t5_timeout_s=float(args.t5_timeout_s),
            t5_max_redirects=int(args.t5_max_redirects),
            t5_max_bytes=int(args.t5_max_bytes),
            t5_block_pattern=[str(p) for p in args.t5_block_pattern],
        )

        rc, stdout_txt, stderr_txt = run_crawl_parse(crawl_argv)
        items = load_pass_items(stdout_txt)

        if not items:
            # run metadata: finished (no items / fail-fast)
            log_loki_event(
                _PIPELINE_LOGGER,
                level=logging.WARNING,
                event="t7_stage_finished",
                source=src,
                stage="stage",
                env=get_crawler_env(),
                run_id=str(run_id),
                app_git_sha=app_git_sha,
                status="no_items",
                crawl_rc=int(rc),
                artifact_dir=artifact_dir,
                elapsed_ms=int((time.monotonic() - t0) * 1000),
                ended_at=datetime.now(timezone.utc).isoformat(),
            )
            # 沒 items 就不做 staging（通常是 T3/T4 fail-fast）
            # 將 stderr 原封不動印出，方便你追查
            sys.stderr.write(stderr_txt)
            return rc if rc != 0 else 2

        gate_artifacts = load_gate_artifacts(artifact_paths)

        # ORM 入庫：同一個交易（run + items + gate_results）
        with SessionLocal() as db:
            staging_counts = stage_snapshot_items(
                db,
                source=args.source,
                note=args.note,
                run_id=run_id,
                snapshot_dir=args.snapshot_dir,
                artifact_dir=base_outdir,
                items=items,
                crawl_rc=int(rc),
                enable_t5=bool(args.enable_t5),
                dq_report=gate_artifacts.dq_report,
                dq_meta=gate_artifacts.dq_meta,
                t5_summary=gate_artifacts.t5_summary,
                t5_meta=gate_artifacts.t5_meta,
            )

        # run metadata: finished (has items staged)
        status = "succeeded" if int(rc) == 0 else "completed_with_warnings"
        log_loki_event(
            _PIPELINE_LOGGER,
            event="t7_stage_finished",
            source=src,
            stage="stage",
            env=get_crawler_env(),
            run_id=str(run_id),
            app_git_sha=app_git_sha,
            status=status,
            crawl_rc=int(rc),
            item_total=int(len(items)),
            item_inserted=int(staging_counts.item_inserted),
            item_updated=int(staging_counts.item_updated),
            gate_inserted=int(staging_counts.gate_inserted),
            gate_updated=int(staging_counts.gate_updated),
            artifact_dir=artifact_dir,
            elapsed_ms=int((time.monotonic() - t0) * 1000),
            ended_at=datetime.now(timezone.utc).isoformat(),
        )

        print(
            json.dumps(
                {
                    "run_id": str(run_id),
                    "crawl_rc": rc,
                    "item_inserted": staging_counts.item_inserted,
                    "item_updated": staging_counts.item_updated,
                    "gate_inserted": staging_counts.gate_inserted,
                    "gate_updated": staging_counts.gate_updated,
                    "artifact_dir": str(base_outdir),
                },
                ensure_ascii=False,
            )
        )

        # 保留 crawl rc，讓 pipeline 能知道是否有 T5 non_match 等問題
        return rc
    except (Exception, SystemExit) as e:
        log_loki_event(
            _PIPELINE_LOGGER,
            level=logging.ERROR,
            event="t7_stage_failed",
            source=src,
            stage="stage",
            env=get_crawler_env(),
            run_id=str(run_id),
            app_git_sha=app_git_sha,
            snapshot_dir=str(args.snapshot_dir),
            artifact_dir=artifact_dir,
            error=str(e),
            exc_type=type(e).__name__,
            elapsed_ms=int((time.monotonic() - t0) * 1000),
            ended_at=datetime.now(timezone.utc).isoformat(),
        )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
