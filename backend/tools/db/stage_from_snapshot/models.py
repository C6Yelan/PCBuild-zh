# backend/tools/db/stage_from_snapshot/models.py
"""Shared models for the T7 stage-from-snapshot runtime."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from backend.tools.db.staging_artifacts import StagingArtifactPaths, StagingGateArtifacts
from backend.tools.db.staging_capture import CrawlParseCapture


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


__all__ = ["StageFromSnapshotCapture", "StageFromSnapshotContext"]
