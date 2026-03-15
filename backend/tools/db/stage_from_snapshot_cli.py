# backend/tools/db/stage_from_snapshot_cli.py
from __future__ import annotations

import argparse
import logging
import time

from backend.core.obs_events import ensure_cli_logging
from backend.tools.db.stage_from_snapshot_runtime import (
    build_stage_from_snapshot_context,
    emit_stage_from_snapshot_no_items,
    emit_stage_from_snapshot_success,
    log_stage_from_snapshot_failed,
    log_stage_from_snapshot_finished,
    log_stage_from_snapshot_started,
    run_stage_from_snapshot_capture,
    stage_snapshot_capture,
)

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
    ensure_cli_logging(logger=_PIPELINE_LOGGER)
    context = build_stage_from_snapshot_context(args)
    artifact_dir: str | None = None
    t0 = time.monotonic()

    log_stage_from_snapshot_started(context, logger=_PIPELINE_LOGGER)

    try:
        capture = run_stage_from_snapshot_capture(context)
        artifact_dir = str(capture.artifact_paths.base_outdir)

        if not capture.crawl_capture.items:
            return emit_stage_from_snapshot_no_items(
                context,
                capture,
                logger=_PIPELINE_LOGGER,
                started_monotonic=t0,
            )

        staging_counts = stage_snapshot_capture(context, capture)
        log_stage_from_snapshot_finished(
            context,
            capture,
            staging_counts,
            logger=_PIPELINE_LOGGER,
            started_monotonic=t0,
        )
        return emit_stage_from_snapshot_success(context, capture, staging_counts)
    except (Exception, SystemExit) as e:
        log_stage_from_snapshot_failed(
            context,
            e,
            logger=_PIPELINE_LOGGER,
            artifact_dir=artifact_dir,
            started_monotonic=t0,
        )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
