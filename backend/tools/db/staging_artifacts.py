# backend/tools/db/staging_artifacts.py
"""Artifact path and gate-summary loaders for staging from a snapshot directory."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from backend.tools.crawler.io.artifact_io import build_artifact_metadata, read_json_file


@dataclass(frozen=True)
class StagingArtifactPaths:
    base_outdir: Path
    dq_outdir: Path
    t5_outdir: Path | None


@dataclass(frozen=True)
class StagingGateArtifacts:
    dq_report: Any
    dq_meta: dict[str, Any] | None
    t5_summary: Any
    t5_meta: dict[str, Any] | None


def resolve_artifact_paths(*, artifact_dir: str | None, run_id: UUID, enable_t5: bool) -> StagingArtifactPaths:
    base_outdir = Path(artifact_dir).resolve() if artifact_dir else (Path("temp") / "t7" / str(run_id))
    return StagingArtifactPaths(
        base_outdir=base_outdir,
        dq_outdir=base_outdir / "dq",
        t5_outdir=(base_outdir / "t5") if enable_t5 else None,
    )


def load_gate_artifacts(paths: StagingArtifactPaths) -> StagingGateArtifacts:
    dq_report_path = paths.dq_outdir / "dq_report.json"
    dq_report = read_json_file(dq_report_path) if dq_report_path.exists() else None
    dq_meta = (
        build_artifact_metadata(dq_report_path, base_dir=paths.base_outdir)
        if dq_report_path.exists()
        else None
    )

    t5_summary = None
    t5_meta = None
    if paths.t5_outdir is not None:
        t5_summary_path = paths.t5_outdir / "t5.summary.json"
        if t5_summary_path.exists():
            t5_summary = read_json_file(t5_summary_path)
            t5_meta = build_artifact_metadata(t5_summary_path, base_dir=paths.base_outdir)

    return StagingGateArtifacts(
        dq_report=dq_report,
        dq_meta=dq_meta,
        t5_summary=t5_summary,
        t5_meta=t5_meta,
    )
