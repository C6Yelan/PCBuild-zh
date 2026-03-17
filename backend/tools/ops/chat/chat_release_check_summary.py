# backend/tools/ops/chat/chat_release_check_summary.py
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Sequence

_P10_CHECK_NAMES = (
    "staged_success",
    "validation_failed",
    "dq_failed",
    "provider_error",
    "retry_backoff",
)
_ReleaseCheckRunner = Callable[[], dict[str, Any]]
_ReleaseCheck = tuple[str, _ReleaseCheckRunner]


def _build_p10_summary(*, snapshot_root: Path) -> dict[str, Any]:
    return {
        "mode": "p10",
        "snapshot_root": str(snapshot_root),
        "passed_checks": [],
        "failed_checks": [],
        "details": {},
    }


def _record_release_check_result(
    summary: dict[str, Any],
    *,
    check_name: str,
    runner: _ReleaseCheckRunner,
) -> None:
    try:
        summary[check_name] = "pass"
        summary["details"][check_name] = runner()
        summary["passed_checks"].append(check_name)
    except Exception as exc:
        summary[check_name] = "fail"
        summary["failed_checks"].append(check_name)
        summary["details"][check_name] = {
            "error_type": type(exc).__name__,
            "message": str(exc),
        }


def _run_release_checks(
    summary: dict[str, Any],
    checks: Sequence[_ReleaseCheck],
) -> None:
    for check_name, runner in checks:
        _record_release_check_result(summary, check_name=check_name, runner=runner)


def _build_p10_setup_failure_summary(exc: Exception) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "mode": "p10",
        "snapshot_root": "-",
        "passed_checks": [],
        "failed_checks": list(_P10_CHECK_NAMES),
        "details": {
            "setup": {
                "error_type": type(exc).__name__,
                "message": str(exc),
            }
        },
    }
    for check_name in _P10_CHECK_NAMES:
        summary[check_name] = "fail"
    return summary
