# backend/tools/crawler/parse/output.py
"""Stdout and stderr emitters for the crawl-parse CLI contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from backend.tools.crawler.dq.reports import format_dq_gate_result_line


def emit_schema_gate_error(report: Any) -> None:
    print(json.dumps(report, ensure_ascii=False, indent=2), file=sys.stderr)


def emit_dq_gate_result(*, report: Any, snapshot_dir: Path) -> None:
    print(
        format_dq_gate_result_line(
            report=report,
            location_key="snapshot_dir",
            location_value=snapshot_dir,
        ),
        file=sys.stderr,
    )


def emit_dq_fail_fast(report: Any) -> None:
    print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), file=sys.stderr)


def emit_stderr(message: str) -> None:
    print(message, file=sys.stderr)


def emit_t5_status(*, summary: dict[str, Any], outdir: Path) -> None:
    print(
        "link_consistency status_counts=%s reason_counts=%s outdir=%s"
        % (summary["status_counts"], summary["reason_counts"], str(outdir)),
        file=sys.stderr,
    )


def emit_stdout_items(items: list[dict[str, Any]]) -> None:
    print(json.dumps(items, ensure_ascii=False, indent=2))
