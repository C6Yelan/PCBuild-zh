"""Run-state, summary, and skip/finalize helpers for incremental crawler runs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from backend.services.crawler.part_registry import resolve_source_parts
from backend.tools.crawler.io.artifact_io import emit_json_stdout, write_json_file

from .incremental_fetch import utc_now


@dataclass(slots=True)
class IncrementalRunContext:
    args: Any
    options: Any
    source: str
    dry_run: bool
    publish_requested: bool
    publish_enabled: bool
    run_id: str
    run_dir: Path
    summary_path: Path
    summary: dict[str, Any]


def build_incremental_run_context(*, args: Any, options: Any) -> IncrementalRunContext:
    run_id = str(uuid4())
    run_dir = (Path("temp") / "t10" / run_id).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    summary_path = run_dir / "summary.json"
    started_at = utc_now()

    dry_run = bool(options.dry_run)
    publish_requested = bool(options.publish)
    publish_enabled = bool(options.publish and not dry_run)
    summary: dict[str, Any] = {
        "run_id": run_id,
        "source": options.source,
        "dry_run": dry_run,
        "publish_requested": publish_requested,
        "publish_enabled": publish_enabled,
        "max_items": int(options.max_items),
        "parts_requested": [],
        "parts": [],
        "counts": {
            "parts_total": 0,
            "parts_changed": 0,
            "parts_no_change": 0,
            "parts_failed": 0,
        },
        "merge": None,
        "publish": None,
        "errors": [],
        "started_at": started_at.isoformat(),
    }
    if publish_requested and dry_run:
        summary["errors"].append("publish_ignored_in_dry_run")

    return IncrementalRunContext(
        args=args,
        options=options,
        source=options.source,
        dry_run=dry_run,
        publish_requested=publish_requested,
        publish_enabled=publish_enabled,
        run_id=run_id,
        run_dir=run_dir,
        summary_path=summary_path,
        summary=summary,
    )


def resolve_incremental_targets(context: IncrementalRunContext) -> tuple[list[tuple[str, Any]], int]:
    try:
        targets = resolve_source_parts(context.source, context.options.parts)
    except Exception as exc:
        context.summary["errors"].append(f"resolve_parts_failed: {exc}")
        return [], 2

    context.summary["parts_requested"] = [part_type for part_type, _ in targets]
    context.summary["counts"]["parts_total"] = len(targets)
    return targets, 0


def log_incremental_start(
    context: IncrementalRunContext,
    *,
    log_event: Callable[..., None],
) -> None:
    log_event(
        event="t10_start",
        source=context.source,
        stage="incremental",
        run_id=context.run_id,
        part_total=int(context.summary["counts"]["parts_total"]),
        dry_run=context.dry_run,
        publish_enabled=context.publish_enabled,
        max_items=int(context.options.max_items),
        requested_parts=context.summary["parts_requested"],
    )


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


__all__ = [
    "IncrementalRunContext",
    "apply_incremental_no_change_phase",
    "build_incremental_run_context",
    "finalize_incremental_run",
    "log_incremental_skip_events",
    "log_incremental_start",
    "record_incremental_unhandled_error",
    "resolve_incremental_targets",
    "set_incremental_skip_summary",
]
