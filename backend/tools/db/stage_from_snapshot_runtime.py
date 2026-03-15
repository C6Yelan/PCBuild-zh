"""Runtime helpers for the T7 stage-from-snapshot CLI."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from pathlib import Path
import sys
import time
from typing import Any
from uuid import UUID, uuid4

from backend.core.obs_events import log_loki_event
from backend.db import SessionLocal
from backend.services.crawler.staging.conventions import get_app_git_sha, get_crawler_env
from backend.tools.crawler.io.artifact_io import emit_json_stdout
from backend.tools.db.staging_artifacts import (
    StagingArtifactPaths,
    StagingGateArtifacts,
    load_gate_artifacts,
    resolve_artifact_paths,
)
from backend.tools.db.staging_capture import (
    CrawlParseCapture,
    build_crawl_parse_argv,
    run_crawl_parse_capture,
)
from backend.tools.db.staging_ingest import StagingCounts, stage_snapshot_items


@dataclass(frozen=True)
class StageFromSnapshotContext:
    args: Any
    run_id: UUID
    source: str
    app_git_sha: str


@dataclass(frozen=True)
class StageFromSnapshotCapture:
    artifact_paths: StagingArtifactPaths
    gate_artifacts: StagingGateArtifacts
    crawl_capture: CrawlParseCapture


def build_stage_from_snapshot_context(args: Any) -> StageFromSnapshotContext:
    run_id = UUID(args.run_id) if args.run_id else uuid4()
    return StageFromSnapshotContext(
        args=args,
        run_id=run_id,
        source=str(args.source),
        app_git_sha=get_app_git_sha(),
    )


def log_stage_from_snapshot_started(
    context: StageFromSnapshotContext,
    *,
    logger: logging.Logger,
) -> None:
    log_loki_event(
        logger,
        event="t7_stage_started",
        source=context.source,
        stage="stage",
        env=get_crawler_env(),
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
        started_at=datetime.now(timezone.utc).isoformat(),
    )


def run_stage_from_snapshot_capture(context: StageFromSnapshotContext) -> StageFromSnapshotCapture:
    artifact_paths = resolve_artifact_paths(
        artifact_dir=context.args.artifact_dir,
        run_id=context.run_id,
        enable_t5=bool(context.args.enable_t5),
    )

    crawl_argv = build_crawl_parse_argv(
        source=context.source,
        snapshot_dir=context.args.snapshot_dir,
        run_id=context.run_id,
        dq_outdir=artifact_paths.dq_outdir,
        t5_outdir=artifact_paths.t5_outdir,
        t5_limit=int(context.args.t5_limit),
        t5_min_interval_ms=int(context.args.t5_min_interval_ms),
        t5_timeout_s=float(context.args.t5_timeout_s),
        t5_max_redirects=int(context.args.t5_max_redirects),
        t5_max_bytes=int(context.args.t5_max_bytes),
        t5_block_pattern=[str(pattern) for pattern in context.args.t5_block_pattern],
    )
    crawl_capture = run_crawl_parse_capture(crawl_argv)
    gate_artifacts = load_gate_artifacts(artifact_paths)
    return StageFromSnapshotCapture(
        artifact_paths=artifact_paths,
        gate_artifacts=gate_artifacts,
        crawl_capture=crawl_capture,
    )


def emit_stage_from_snapshot_no_items(
    context: StageFromSnapshotContext,
    capture: StageFromSnapshotCapture,
    *,
    logger: logging.Logger,
    started_monotonic: float,
) -> int:
    log_loki_event(
        logger,
        level=logging.WARNING,
        event="t7_stage_finished",
        source=context.source,
        stage="stage",
        env=get_crawler_env(),
        run_id=str(context.run_id),
        app_git_sha=context.app_git_sha,
        status="no_items",
        crawl_rc=int(capture.crawl_capture.rc),
        artifact_dir=str(capture.artifact_paths.base_outdir),
        elapsed_ms=elapsed_milliseconds(started_monotonic),
        ended_at=datetime.now(timezone.utc).isoformat(),
    )
    print(capture.crawl_capture.stderr_txt, end="", file=sys.stderr)
    if capture.crawl_capture.rc != 0:
        return int(capture.crawl_capture.rc)
    return 2


def stage_snapshot_capture(
    context: StageFromSnapshotContext,
    capture: StageFromSnapshotCapture,
) -> StagingCounts:
    with SessionLocal() as db:
        return stage_snapshot_items(
            db,
            source=context.source,
            note=context.args.note,
            run_id=context.run_id,
            snapshot_dir=context.args.snapshot_dir,
            artifact_dir=capture.artifact_paths.base_outdir,
            items=capture.crawl_capture.items,
            crawl_rc=int(capture.crawl_capture.rc),
            enable_t5=bool(context.args.enable_t5),
            dq_report=capture.gate_artifacts.dq_report,
            dq_meta=capture.gate_artifacts.dq_meta,
            t5_summary=capture.gate_artifacts.t5_summary,
            t5_meta=capture.gate_artifacts.t5_meta,
        )


def log_stage_from_snapshot_finished(
    context: StageFromSnapshotContext,
    capture: StageFromSnapshotCapture,
    staging_counts: StagingCounts,
    *,
    logger: logging.Logger,
    started_monotonic: float,
) -> None:
    status = "succeeded" if int(capture.crawl_capture.rc) == 0 else "completed_with_warnings"
    log_loki_event(
        logger,
        event="t7_stage_finished",
        source=context.source,
        stage="stage",
        env=get_crawler_env(),
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
        elapsed_ms=elapsed_milliseconds(started_monotonic),
        ended_at=datetime.now(timezone.utc).isoformat(),
    )


def emit_stage_from_snapshot_success(
    context: StageFromSnapshotContext,
    capture: StageFromSnapshotCapture,
    staging_counts: StagingCounts,
) -> int:
    emit_json_stdout(
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


def log_stage_from_snapshot_failed(
    context: StageFromSnapshotContext,
    error: Exception | SystemExit,
    *,
    logger: logging.Logger,
    artifact_dir: str | None,
    started_monotonic: float,
) -> None:
    log_loki_event(
        logger,
        level=logging.ERROR,
        event="t7_stage_failed",
        source=context.source,
        stage="stage",
        env=get_crawler_env(),
        run_id=str(context.run_id),
        app_git_sha=context.app_git_sha,
        snapshot_dir=str(context.args.snapshot_dir),
        artifact_dir=artifact_dir,
        error=str(error),
        exc_type=type(error).__name__,
        elapsed_ms=elapsed_milliseconds(started_monotonic),
        ended_at=datetime.now(timezone.utc).isoformat(),
    )


def elapsed_milliseconds(started_monotonic: float) -> int:
    return int((time.monotonic() - started_monotonic) * 1000)


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
