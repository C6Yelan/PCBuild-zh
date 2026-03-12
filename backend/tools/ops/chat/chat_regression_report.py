"""Official chat ops CLI: comparable regression report generation."""

# backend/tools/ops/chat_regression_report.py
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from backend.services.chat.config import get_ai_settings
from backend.services.chat.health import run_provider_health_check
from backend.services.chat.reporting import (
    REPORT_FILENAME_SAFE_RE,
    build_timestamped_report_path,
    sanitize_report_filename_component,
    write_report_payload,
)


_FILENAME_SAFE_RE = REPORT_FILENAME_SAFE_RE
_sanitize_filename_component = sanitize_report_filename_component


def _build_regression_report(health_report: dict[str, object]) -> dict[str, object]:
    cases = list(health_report.get("cases", []))

    def _error_count(error_type: str) -> int:
        return sum(1 for case in cases if case.get("error_type") == error_type)

    return {
        "provider": health_report.get("provider"),
        "model": health_report.get("model"),
        "ran_at": health_report.get("ran_at"),
        "total_cases": health_report.get("total_cases", 0),
        "passed_cases": health_report.get("passed_cases", 0),
        "failed_cases": health_report.get("failed_cases", 0),
        "gate_fail_cases": _error_count("validation_failed"),
        "dq_fail_cases": _error_count("dq_failed"),
        "timeout_cases": _error_count("timeout"),
        "rate_limit_cases": _error_count("429"),
        "network_error_cases": _error_count("network_error"),
        "latency_ms_p50": health_report.get("latency_ms_p50", 0),
        "latency_ms_p95": health_report.get("latency_ms_p95", 0),
        "cases": [
            {
                "request_id": case.get("request_id"),
                "ok": case.get("ok"),
                "error_type": case.get("error_type"),
                "latency_ms": case.get("latency_ms"),
                "warnings": case.get("warnings"),
            }
            for case in cases
        ],
    }


_write_report = write_report_payload


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run provider smoke prompts and emit a comparable regression report."
    )
    parser.parse_args(argv)

    settings = get_ai_settings()
    health_report = run_provider_health_check()
    regression_report = _build_regression_report(health_report)

    report_path = build_timestamped_report_path(
        root_dir=Path(settings.ai_raw_snapshot_dir),
        report_dir_name="regression_reports",
        provider=settings.ai_provider,
        model=settings.ai_model,
        ran_at=datetime.now(timezone.utc),
    )
    regression_report["report_path"] = str(report_path)
    _write_report(report_path, regression_report)

    print(json.dumps(regression_report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if regression_report["failed_cases"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
