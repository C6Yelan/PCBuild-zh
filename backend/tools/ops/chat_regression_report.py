# backend/tools/ops/chat_regression_report.py
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from backend.services.chat.config import get_ai_settings
from backend.services.chat.health import run_provider_health_check


_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _sanitize_filename_component(value: str, fallback: str) -> str:
    normalized = _FILENAME_SAFE_RE.sub("_", value).strip("._")
    return normalized or fallback


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


def _write_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run provider smoke prompts and emit a comparable regression report."
    )
    parser.parse_args(argv)

    settings = get_ai_settings()
    health_report = run_provider_health_check()
    regression_report = _build_regression_report(health_report)

    ran_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_provider = _sanitize_filename_component(settings.ai_provider, "unknown-provider")
    safe_model = _sanitize_filename_component(settings.ai_model, "unknown-model")
    report_path = (
        Path(settings.ai_raw_snapshot_dir)
        / "regression_reports"
        / f"{ran_at}__{safe_provider}__{safe_model}.json"
    )
    regression_report["report_path"] = str(report_path)
    _write_report(report_path, regression_report)

    print(json.dumps(regression_report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if regression_report["failed_cases"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
