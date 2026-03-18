# backend/tools/db/stage_from_snapshot/capture_runtime.py
"""Capture and staging runtime helpers for the stage-from-snapshot path."""

from __future__ import annotations

from typing import Any, Callable
from uuid import UUID

from backend.tools.db.stage_from_snapshot.models import (
    StageFromSnapshotCapture,
    StageFromSnapshotContext,
)


def build_stage_from_snapshot_context(
    args: Any,
    *,
    uuid_factory: Callable[[], UUID],
    get_app_git_sha_fn: Callable[[], str],
) -> StageFromSnapshotContext:
    run_id = UUID(args.run_id) if args.run_id else uuid_factory()
    return StageFromSnapshotContext(
        args=args,
        run_id=run_id,
        source=str(args.source),
        app_git_sha=get_app_git_sha_fn(),
    )


def run_stage_from_snapshot_capture(
    context: StageFromSnapshotContext,
    *,
    resolve_artifact_paths_fn: Callable[..., Any],
    build_crawl_parse_argv_fn: Callable[..., list[str]],
    run_crawl_parse_capture_fn: Callable[[list[str]], Any],
    load_gate_artifacts_fn: Callable[[Any], Any],
) -> StageFromSnapshotCapture:
    artifact_paths = resolve_artifact_paths_fn(
        artifact_dir=context.args.artifact_dir,
        run_id=context.run_id,
        enable_t5=bool(context.args.enable_t5),
    )

    crawl_argv = build_crawl_parse_argv_fn(
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
    crawl_capture = run_crawl_parse_capture_fn(crawl_argv)
    gate_artifacts = load_gate_artifacts_fn(artifact_paths)

    return StageFromSnapshotCapture(
        artifact_paths=artifact_paths,
        gate_artifacts=gate_artifacts,
        crawl_capture=crawl_capture,
    )


def stage_snapshot_capture(
    context: StageFromSnapshotContext,
    capture: StageFromSnapshotCapture,
    *,
    session_factory: Callable[[], Any],
    stage_snapshot_items_fn: Callable[..., Any],
) -> Any:
    with session_factory() as db:
        return stage_snapshot_items_fn(
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


__all__ = [
    "build_stage_from_snapshot_context",
    "run_stage_from_snapshot_capture",
    "stage_snapshot_capture",
]
