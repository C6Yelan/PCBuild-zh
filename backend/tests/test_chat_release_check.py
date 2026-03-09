# backend/tests/test_chat_release_check.py
from __future__ import annotations

import json

import backend.tools.ops.chat_release_check as chat_release_check


def _parse_stdout_json(stdout: str) -> dict[str, object]:
    lines = stdout.strip().splitlines()
    if lines and lines[-1] == "P10_CHECK_OK":
        lines = lines[:-1]
    return json.loads("\n".join(lines))


def test_chat_release_check_main_returns_zero_when_all_checks_pass(
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        chat_release_check,
        "run_p10_release_check",
        lambda: {
            "mode": "p10",
            "snapshot_root": "/tmp/release-check",
            "staged_success": "pass",
            "validation_failed": "pass",
            "dq_failed": "pass",
            "provider_error": "pass",
            "retry_backoff": "pass",
            "passed_checks": [
                "staged_success",
                "validation_failed",
                "dq_failed",
                "provider_error",
                "retry_backoff",
            ],
            "failed_checks": [],
            "details": {},
        },
    )

    exit_code = chat_release_check.main(["--mode", "p10"])

    stdout = capsys.readouterr().out
    assert exit_code == 0
    assert "P10_CHECK_OK" in stdout
    payload = _parse_stdout_json(stdout)
    assert payload["staged_success"] == "pass"
    assert payload["failed_checks"] == []


def test_chat_release_check_main_returns_two_when_any_check_fails(
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        chat_release_check,
        "run_p10_release_check",
        lambda: {
            "mode": "p10",
            "snapshot_root": "/tmp/release-check",
            "staged_success": "pass",
            "validation_failed": "fail",
            "dq_failed": "pass",
            "provider_error": "pass",
            "retry_backoff": "pass",
            "passed_checks": [
                "staged_success",
                "dq_failed",
                "provider_error",
                "retry_backoff",
            ],
            "failed_checks": ["validation_failed"],
            "details": {
                "validation_failed": {
                    "error_type": "AssertionError",
                    "message": "expected validation_failed",
                }
            },
        },
    )

    exit_code = chat_release_check.main(["--mode", "p10"])

    stdout = capsys.readouterr().out
    assert exit_code == 2
    assert "P10_CHECK_OK" not in stdout
    payload = _parse_stdout_json(stdout)
    assert payload["validation_failed"] == "fail"
    assert payload["failed_checks"] == ["validation_failed"]


def test_chat_release_check_summary_shape_is_stable(
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        chat_release_check,
        "run_p10_release_check",
        lambda: {
            "mode": "p10",
            "snapshot_root": "/tmp/release-check",
            "staged_success": "pass",
            "validation_failed": "pass",
            "dq_failed": "pass",
            "provider_error": "pass",
            "retry_backoff": "pass",
            "passed_checks": ["staged_success"],
            "failed_checks": [],
            "details": {"staged_success": {"request_id": "req-1"}},
        },
    )

    chat_release_check.main(["--mode", "p10"])

    payload = _parse_stdout_json(capsys.readouterr().out)
    assert payload["mode"] == "p10"
    assert payload["snapshot_root"] == "/tmp/release-check"
    assert set(
        [
            "staged_success",
            "validation_failed",
            "dq_failed",
            "provider_error",
            "retry_backoff",
            "passed_checks",
            "failed_checks",
            "snapshot_root",
            "details",
        ]
    ).issubset(payload.keys())
