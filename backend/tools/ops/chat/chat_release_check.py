"""Deterministic chat acceptance harness.

Keep the CLI module path stable for existing SOP/CI usage, but treat this file
as test-harness surface rather than official runtime ops.
"""

# backend/tools/ops/chat_release_check.py
from __future__ import annotations

import argparse
from typing import Any, Sequence

from backend.tools.ops.chat.chat_artifact_helpers import emit_json_payload, read_json_artifact
from backend.tools.ops.chat.chat_release_check_patching import _isolated_snapshot_root, _run_service_case
from backend.tools.ops.chat.chat_release_check_scenarios import _build_p10_checks
from backend.tools.ops.chat.chat_release_check_summary import (
    _build_p10_setup_failure_summary,
    _build_p10_summary,
    _run_release_checks,
)


def run_p10_release_check() -> dict[str, Any]:
    snapshot_root = _isolated_snapshot_root()
    summary = _build_p10_summary(snapshot_root=snapshot_root)
    checks = _build_p10_checks(
        snapshot_root,
        read_json_artifact=read_json_artifact,
        run_service_case=_run_service_case,
    )
    _run_release_checks(summary, checks)
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run deterministic release checks for chat ops.")
    parser.add_argument("--mode", default="p10", choices=["p10"])
    parser.parse_args(argv)

    try:
        summary = run_p10_release_check()
    except Exception as exc:
        summary = _build_p10_setup_failure_summary(exc)
    emit_json_payload(summary)
    if not summary["failed_checks"]:
        print("P10_CHECK_OK")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
