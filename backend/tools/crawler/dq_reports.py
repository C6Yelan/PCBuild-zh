# backend/tools/crawler/dq_reports.py
"""Shared DQ report writers and stderr line formatters for crawler CLIs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from backend.tools.crawler.artifact_io import write_json_atomic, write_json_file


def write_dq_artifacts(
    *,
    outdir: str | Path,
    report: dict[str, Any],
    passed_items: list[dict[str, Any]],
    quarantined_items: list[dict[str, Any]],
    atomic: bool = False,
) -> None:
    path = Path(outdir).resolve()
    writer = write_json_atomic if atomic else write_json_file
    writer(path / "dq_report.json", report)
    writer(path / "dq_pass.json", passed_items)
    writer(path / "dq_quarantine.json", quarantined_items)


def format_dq_gate_result_line(*, report: Any, location_key: str, location_value: str | Path) -> str:
    return (
        "category=dq event=dq_gate_result part=%s total=%d passed=%d quarantined=%d "
        "errors=%d warnings=%d infos=%d %s=%s"
        % (
            report.category,
            report.total,
            report.passed,
            report.quarantined,
            report.errors,
            report.warnings,
            report.infos,
            location_key,
            str(location_value),
        )
    )
