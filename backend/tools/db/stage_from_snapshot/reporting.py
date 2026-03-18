# backend/tools/db/stage_from_snapshot/reporting.py
"""Reporting facade for the stage-from-snapshot runtime."""

from __future__ import annotations

import sys
import time
from typing import Any, TextIO

from backend.tools.db.stage_from_snapshot.event_reporting import (
    log_stage_from_snapshot_failed,
    log_stage_from_snapshot_finished,
    log_stage_from_snapshot_started,
)
from backend.tools.db.stage_from_snapshot.models import (
    StageFromSnapshotCapture,
    StageFromSnapshotContext,
)
from backend.tools.db.stage_from_snapshot.result_reporting import (
    emit_stage_from_snapshot_no_items as emit_stage_from_snapshot_no_items_runtime,
    emit_stage_from_snapshot_success,
)
from backend.tools.db.staging_ingest_support.models import StagingCounts


def emit_stage_from_snapshot_no_items(
    context: StageFromSnapshotContext,
    capture: StageFromSnapshotCapture,
    *,
    logger: Any,
    log_event_fn: Any,
    env_value: str,
    ended_at: str,
    elapsed_ms: int,
    stderr_stream: TextIO = sys.stderr,
) -> int:
    return emit_stage_from_snapshot_no_items_runtime(
        context,
        capture,
        logger=logger,
        log_event_fn=log_event_fn,
        env_value=env_value,
        ended_at=ended_at,
        elapsed_ms=elapsed_ms,
        stderr_stream=stderr_stream,
    )


def elapsed_milliseconds(started_monotonic: float) -> int:
    return int((time.monotonic() - started_monotonic) * 1000)


__all__ = [
    "elapsed_milliseconds",
    "emit_stage_from_snapshot_no_items",
    "emit_stage_from_snapshot_success",
    "log_stage_from_snapshot_failed",
    "log_stage_from_snapshot_finished",
    "log_stage_from_snapshot_started",
]
