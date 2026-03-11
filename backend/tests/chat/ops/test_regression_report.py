from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import backend.tools.ops.chat_regression_report as chat_regression_report


def test_chat_regression_report_writes_file_and_returns_exit_code(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    monkeypatch.setattr(
        chat_regression_report,
        "get_ai_settings",
        lambda: SimpleNamespace(
            ai_raw_snapshot_dir=str(tmp_path),
            ai_provider="openai_compat",
            ai_model="gpt-4o-mini",
        ),
    )
    monkeypatch.setattr(
        chat_regression_report,
        "run_provider_health_check",
        lambda: {
            "provider": "openai_compat",
            "model": "gpt-4o-mini",
            "ran_at": "2026-03-09T00:00:00Z",
            "total_cases": 5,
            "passed_cases": 4,
            "failed_cases": 1,
            "latency_ms_p50": 120,
            "latency_ms_p95": 180,
            "cases": [
                {
                    "request_id": "req-1",
                    "ok": True,
                    "error_type": None,
                    "latency_ms": 100,
                    "warnings": None,
                },
                {
                    "request_id": "req-2",
                    "ok": False,
                    "error_type": "dq_failed",
                    "latency_ms": 200,
                    "warnings": ["usage_unavailable"],
                },
            ],
        },
    )

    exit_code = chat_regression_report.main([])

    assert exit_code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["dq_fail_cases"] == 1
    assert payload["failed_cases"] == 1
    assert Path(payload["report_path"]).exists()
