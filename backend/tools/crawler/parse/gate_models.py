# backend/tools/crawler/parse/gate_models.py
"""Shared gate runtime config and outcome models."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backend.tools.crawler.parse.artifacts import T5ArtifactPaths


@dataclass(frozen=True)
class T5GateConfig:
    source: str
    run_id: str | None
    app_git_sha: str
    snapshot_dir: Path
    artifacts: T5ArtifactPaths
    limit: int
    min_interval_ms: int
    timeout_s: float
    max_redirects: int
    max_bytes: int
    block_patterns: list[str]


@dataclass(frozen=True)
class T5GateOutcome:
    rc: int
    summary: dict[str, Any] | None
    passed_items: list[dict[str, Any]]
    quarantined_items: list[dict[str, Any]]
    error_message: str | None


__all__ = ["T5GateConfig", "T5GateOutcome"]
