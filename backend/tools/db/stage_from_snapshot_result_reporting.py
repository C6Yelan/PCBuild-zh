"""Branch/result emit helpers for the T7 snapshot runtime."""

from __future__ import annotations

import logging
from typing import Any, TextIO

from backend.tools.db.stage_from_snapshot_models import (
    StageFromSnapshotCapture,
    StageFromSnapshotContext,
)
from backend.tools.db.staging_ingest_models import StagingCounts


def emit_stage_from_snapshot_no_items(
    context: StageFromSnapshotContext,
    capture: StageFromSnapshotCapture,
    *,
    logger: Any,
    log_event_fn: Any,
    env_value: str,
    ended_at: str,
    elapsed_ms: int,
    stderr_stream: TextIO,
) -> int:
    log_event_fn(
        logger,
        level=logging.WARNING,
        event="t7_stage_finished",
        source=context.source,
        stage="stage",
        env=env_value,
        run_id=str(context.run_id),
        app_git_sha=context.app_git_sha,
        status="no_items",
        crawl_rc=int(capture.crawl_capture.rc),
        artifact_dir=str(capture.artifact_paths.base_outdir),
        elapsed_ms=elapsed_ms,
        ended_at=ended_at,
    )
    print(capture.crawl_capture.stderr_txt, end="", file=stderr_stream)
    if capture.crawl_capture.rc != 0:
        return int(capture.crawl_capture.rc)
    return 2


def emit_stage_from_snapshot_success(
    context: StageFromSnapshotContext,
    capture: StageFromSnapshotCapture,
    staging_counts: StagingCounts,
    *,
    emit_json_stdout_fn: Any,
) -> int:
    emit_json_stdout_fn(
        {
            "run_id": str(context.run_id),
            "crawl_rc": int(capture.crawl_capture.rc),
            "item_inserted": staging_counts.item_inserted,
            "item_updated": staging_counts.item_updated,
            "gate_inserted": staging_counts.gate_inserted,
            "gate_updated": staging_counts.gate_updated,
            "artifact_dir": str(capture.artifact_paths.base_outdir),
        }
    )
    return int(capture.crawl_capture.rc)
