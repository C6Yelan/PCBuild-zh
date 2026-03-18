# backend/tools/db/stage_from_snapshot_result_reporting.py
"""Compatibility shim for the canonical stage-from-snapshot result reporting package."""

from backend.tools.db.stage_from_snapshot.result_reporting import (
    emit_stage_from_snapshot_no_items,
    emit_stage_from_snapshot_success,
)

__all__ = ["emit_stage_from_snapshot_no_items", "emit_stage_from_snapshot_success"]
