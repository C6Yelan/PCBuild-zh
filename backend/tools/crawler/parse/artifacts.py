# backend/tools/crawler/parse/artifacts.py
"""Artifact path and report writers for the crawl-parse CLI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backend.tools.crawler.dq.reports import write_dq_artifacts as write_shared_dq_artifacts
from backend.tools.crawler.io.artifact_io import write_json_atomic


@dataclass(frozen=True)
class T5ArtifactPaths:
    outdir: Path
    input_path: Path
    report_path: Path
    summary_path: Path
    passed_path: Path
    quarantine_path: Path


def write_dq_artifacts(
    *,
    outdir: str,
    report: dict[str, Any],
    passed_items: list[dict[str, Any]],
    quarantined_items: list[dict[str, Any]],
) -> None:
    write_shared_dq_artifacts(
        outdir=outdir,
        report=report,
        passed_items=passed_items,
        quarantined_items=quarantined_items,
        atomic=True,
    )


def resolve_t5_artifact_paths(outdir: str) -> T5ArtifactPaths:
    path = Path(outdir).resolve()
    return T5ArtifactPaths(
        outdir=path,
        input_path=path / "t5.input.json",
        report_path=path / "t5.link_report.jsonl",
        summary_path=path / "t5.summary.json",
        passed_path=path / "t5.passed.json",
        quarantine_path=path / "t5.quarantine.json",
    )


def write_t5_input(paths: T5ArtifactPaths, items: list[dict[str, Any]]) -> None:
    write_json_atomic(paths.input_path, items)


def write_t5_outputs(
    paths: T5ArtifactPaths,
    *,
    summary: dict[str, Any],
    passed_items: list[dict[str, Any]],
    quarantined_items: list[dict[str, Any]],
) -> None:
    write_json_atomic(paths.summary_path, summary)
    write_json_atomic(paths.passed_path, passed_items)
    write_json_atomic(paths.quarantine_path, quarantined_items)
