# backend/tools/db/stage_from_snapshot_models.py
"""Compatibility shim for the canonical T7 stage-from-snapshot models package."""

from backend.tools.db.stage_from_snapshot.models import StageFromSnapshotCapture, StageFromSnapshotContext

__all__ = ["StageFromSnapshotCapture", "StageFromSnapshotContext"]
