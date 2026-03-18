# backend/tools/db/stage_from_snapshot/event_reporting.py
"""Event logging helpers for the stage-from-snapshot runtime."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from backend.tools.db.stage_from_snapshot.models import (
    StageFromSnapshotCapture,
    StageFromSnapshotContext,
)
from backend.tools.db.staging_ingest_support.models import StagingCounts


def log_stage_from_snapshot_started(
    context: StageFromSnapshotContext,
    *,
    logger: logging.Logger,
    log_event_fn: Any,
    env_value: str,
    started_at: str,
) -> None:
    log_event_fn(
        logger,
        event="t7_stage_started",
        source=context.source,
        stage="stage",
        env=env_value,
        run_id=str(context.run_id),
        app_git_sha=context.app_git_sha,
        snapshot_dir=str(context.args.snapshot_dir),
        snapshot_name=str(Path(context.args.snapshot_dir).name),
        enable_t5=bool(context.args.enable_t5),
        t5_limit=int(context.args.t5_limit),
        t5_min_interval_ms=int(context.args.t5_min_interval_ms),
        t5_timeout_s=float(context.args.t5_timeout_s),
        t5_max_redirects=int(context.args.t5_max_redirects),
        t5_max_bytes=int(context.args.t5_max_bytes),
        started_at=started_at,
    )


def log_stage_from_snapshot_finished(
    context: StageFromSnapshotContext,
    capture: StageFromSnapshotCapture,
    staging_counts: StagingCounts,
    *,
    logger: logging.Logger,
    log_event_fn: Any,
    env_value: str,
    ended_at: str,
    elapsed_ms: int,
) -> None:
    status = "succeeded" if int(capture.crawl_capture.rc) == 0 else "completed_with_warnings"
    log_event_fn(
        logger,
        event="t7_stage_finished",
        source=context.source,
        stage="stage",
        env=env_value,
        run_id=str(context.run_id),
        app_git_sha=context.app_git_sha,
        status=status,
        crawl_rc=int(capture.crawl_capture.rc),
        item_total=int(len(capture.crawl_capture.items)),
        item_inserted=int(staging_counts.item_inserted),
        item_updated=int(staging_counts.item_updated),
        gate_inserted=int(staging_counts.gate_inserted),
        gate_updated=int(staging_counts.gate_updated),
        artifact_dir=str(capture.artifact_paths.base_outdir),
        elapsed_ms=elapsed_ms,
        ended_at=ended_at,
    )


def log_stage_from_snapshot_failed(
    context: StageFromSnapshotContext,
    error: Exception | SystemExit,
    *,
    logger: logging.Logger,
    artifact_dir: str | None,
    log_event_fn: Any,
    env_value: str,
    ended_at: str,
    elapsed_ms: int,
) -> None:
    log_event_fn(
        logger,
        level=logging.ERROR,
        event="t7_stage_failed",
        source=context.source,
        stage="stage",
        env=env_value,
        run_id=str(context.run_id),
        app_git_sha=context.app_git_sha,
        snapshot_dir=str(context.args.snapshot_dir),
        artifact_dir=artifact_dir,
        error=str(error),
        exc_type=type(error).__name__,
        elapsed_ms=elapsed_ms,
        ended_at=ended_at,
    )
