# backend/tools/db/stage_from_snapshot_capture_runtime.py
"""Compatibility shim for the canonical T7 capture runtime package."""

from backend.tools.db.stage_from_snapshot.capture_runtime import (
    build_stage_from_snapshot_context,
    run_stage_from_snapshot_capture,
    stage_snapshot_capture,
)

__all__ = [
    "build_stage_from_snapshot_context",
    "run_stage_from_snapshot_capture",
    "stage_snapshot_capture",
]
