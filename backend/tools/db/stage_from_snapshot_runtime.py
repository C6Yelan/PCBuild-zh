# backend/tools/db/stage_from_snapshot_runtime.py
"""Thin public facade for the stage-from-snapshot runtime."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import sys
from typing import Any
from uuid import uuid4

from backend.core.obs_events import log_loki_event
from backend.db import SessionLocal
from backend.services.crawler.staging.conventions import get_app_git_sha, get_crawler_env
from backend.tools.crawler.io.artifact_io import emit_json_stdout
from backend.tools.db.stage_from_snapshot.capture_runtime import (
    build_stage_from_snapshot_context as build_stage_from_snapshot_context_runtime,
    run_stage_from_snapshot_capture as run_stage_from_snapshot_capture_runtime,
    stage_snapshot_capture as stage_snapshot_capture_runtime,
)
from backend.tools.db.stage_from_snapshot.models import (
    StageFromSnapshotCapture,
    StageFromSnapshotContext,
)
from backend.tools.db.stage_from_snapshot.reporting import (
    elapsed_milliseconds,
    emit_stage_from_snapshot_no_items as emit_stage_from_snapshot_no_items_runtime,
    emit_stage_from_snapshot_success as emit_stage_from_snapshot_success_runtime,
    log_stage_from_snapshot_failed as log_stage_from_snapshot_failed_runtime,
    log_stage_from_snapshot_finished as log_stage_from_snapshot_finished_runtime,
    log_stage_from_snapshot_started as log_stage_from_snapshot_started_runtime,
)
from backend.tools.db.staging_artifacts import load_gate_artifacts, resolve_artifact_paths
from backend.tools.db.staging_capture import build_crawl_parse_argv, run_crawl_parse_capture
from backend.tools.db.staging_ingest import stage_snapshot_items
from backend.tools.db.staging_ingest_support.models import StagingCounts


def build_stage_from_snapshot_context(args: Any) -> StageFromSnapshotContext:
    return build_stage_from_snapshot_context_runtime(
        args,
        uuid_factory=uuid4,
        get_app_git_sha_fn=get_app_git_sha,
    )


def log_stage_from_snapshot_started(
    context: StageFromSnapshotContext,
    *,
    logger: logging.Logger,
) -> None:
    return log_stage_from_snapshot_started_runtime(
        context,
        logger=logger,
        log_event_fn=log_loki_event,
        env_value=get_crawler_env(),
        started_at=datetime.now(timezone.utc).isoformat(),
    )


def run_stage_from_snapshot_capture(context: StageFromSnapshotContext) -> StageFromSnapshotCapture:
    return run_stage_from_snapshot_capture_runtime(
        context,
        resolve_artifact_paths_fn=resolve_artifact_paths,
        build_crawl_parse_argv_fn=build_crawl_parse_argv,
        run_crawl_parse_capture_fn=run_crawl_parse_capture,
        load_gate_artifacts_fn=load_gate_artifacts,
    )


def emit_stage_from_snapshot_no_items(
    context: StageFromSnapshotContext,
    capture: StageFromSnapshotCapture,
    *,
    logger: logging.Logger,
    started_monotonic: float,
) -> int:
    return emit_stage_from_snapshot_no_items_runtime(
        context,
        capture,
        logger=logger,
        log_event_fn=log_loki_event,
        env_value=get_crawler_env(),
        ended_at=datetime.now(timezone.utc).isoformat(),
        elapsed_ms=elapsed_milliseconds(started_monotonic),
        stderr_stream=sys.stderr,
    )


def stage_snapshot_capture(
    context: StageFromSnapshotContext,
    capture: StageFromSnapshotCapture,
) -> StagingCounts:
    return stage_snapshot_capture_runtime(
        context,
        capture,
        session_factory=SessionLocal,
        stage_snapshot_items_fn=stage_snapshot_items,
    )


def log_stage_from_snapshot_finished(
    context: StageFromSnapshotContext,
    capture: StageFromSnapshotCapture,
    staging_counts: StagingCounts,
    *,
    logger: logging.Logger,
    started_monotonic: float,
) -> None:
    return log_stage_from_snapshot_finished_runtime(
        context,
        capture,
        staging_counts,
        logger=logger,
        log_event_fn=log_loki_event,
        env_value=get_crawler_env(),
        ended_at=datetime.now(timezone.utc).isoformat(),
        elapsed_ms=elapsed_milliseconds(started_monotonic),
    )


def emit_stage_from_snapshot_success(
    context: StageFromSnapshotContext,
    capture: StageFromSnapshotCapture,
    staging_counts: StagingCounts,
) -> int:
    return emit_stage_from_snapshot_success_runtime(
        context,
        capture,
        staging_counts,
        emit_json_stdout_fn=emit_json_stdout,
    )


def log_stage_from_snapshot_failed(
    context: StageFromSnapshotContext,
    error: Exception | SystemExit,
    *,
    logger: logging.Logger,
    artifact_dir: str | None,
    started_monotonic: float,
) -> None:
    return log_stage_from_snapshot_failed_runtime(
        context,
        error,
        logger=logger,
        artifact_dir=artifact_dir,
        log_event_fn=log_loki_event,
        env_value=get_crawler_env(),
        ended_at=datetime.now(timezone.utc).isoformat(),
        elapsed_ms=elapsed_milliseconds(started_monotonic),
    )


__all__ = [
    "StageFromSnapshotCapture",
    "StageFromSnapshotContext",
    "build_stage_from_snapshot_context",
    "elapsed_milliseconds",
    "emit_stage_from_snapshot_no_items",
    "emit_stage_from_snapshot_success",
    "log_stage_from_snapshot_failed",
    "log_stage_from_snapshot_finished",
    "log_stage_from_snapshot_started",
    "run_stage_from_snapshot_capture",
    "stage_snapshot_capture",
]
