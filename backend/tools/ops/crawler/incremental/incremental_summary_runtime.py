# backend/tools/ops/crawler/incremental/incremental_summary_runtime.py
"""Summary/finalize helpers for incremental crawler runs."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

from backend.tools.crawler.io.artifact_io import emit_json_stdout, write_json_file

from .incremental_context_runtime import IncrementalRunContext
from .incremental_fetch_state import utc_now


def set_incremental_skip_summary(
    summary: dict[str, Any],
    *,
    merge_rc: int | None,
    publish_rc: int | None,
    reason: str,
    published: bool = False,
) -> None:
    summary["merge"] = {"rc": merge_rc, "reason": reason}
    summary["publish"] = {"rc": publish_rc, "published": published, "reason": reason}


def log_incremental_skip_events(
    *,
    log_event: Callable[..., None],
    source: str,
    run_id: str,
    rc: int,
    reason: str,
    changed_part_total: int,
    published: bool = False,
) -> None:
    log_event(
        event="t10_merge_done",
        source=source,
        stage="merge",
        run_id=run_id,
        part_type="all",
        rc=rc,
        changed_part_total=int(changed_part_total),
        skipped=True,
        reason=reason,
    )
    log_event(
        event="t10_publish_done",
        source=source,
        stage="publish",
        run_id=run_id,
        part_type="all",
        rc=rc,
        published=published,
        reason=reason,
    )


def apply_incremental_no_change_phase(
    context: IncrementalRunContext,
    *,
    current_rc: int,
    log_event: Callable[..., None],
) -> int:
    skip_reason = "skipped_no_changed_parts" if current_rc == 0 else "skipped_due_to_errors"
    skip_rc = 0 if current_rc == 0 else 2
    set_incremental_skip_summary(
        context.summary,
        merge_rc=skip_rc,
        publish_rc=skip_rc,
        reason=skip_reason,
        published=False,
    )
    log_incremental_skip_events(
        log_event=log_event,
        source=context.source,
        run_id=context.run_id,
        rc=skip_rc,
        reason=skip_reason,
        changed_part_total=0,
        published=False,
    )
    return skip_rc


def record_incremental_unhandled_error(
    context: IncrementalRunContext,
    exc: Exception,
) -> None:
    context.summary["errors"].append(f"unhandled_error: {exc}")
    context.summary["errors"].append(f"exc_type: {type(exc).__name__}")
    if context.summary["merge"] is None:
        context.summary["merge"] = {"rc": None, "reason": "skipped_due_to_errors"}
    if context.summary["publish"] is None:
        context.summary["publish"] = {"rc": None, "published": False, "reason": "skipped_due_to_errors"}


def finalize_incremental_run(
    context: IncrementalRunContext,
    *,
    rc: int,
) -> int:
    ended_at = utc_now()
    context.summary["ended_at"] = ended_at.isoformat()
    started_at = datetime.fromisoformat(str(context.summary["started_at"]))
    elapsed_ms = int((ended_at - started_at).total_seconds() * 1000)
    context.summary["elapsed_ms"] = elapsed_ms
    context.summary["exit_code"] = int(rc)
    write_json_file(context.summary_path, context.summary)
    emit_json_stdout(
        {
            "run_id": context.run_id,
            "summary_path": str(context.summary_path),
            "exit_code": int(rc),
            "changed_parts": int(context.summary["counts"]["parts_changed"]),
            "no_change_parts": int(context.summary["counts"]["parts_no_change"]),
        }
    )
    return int(rc)
