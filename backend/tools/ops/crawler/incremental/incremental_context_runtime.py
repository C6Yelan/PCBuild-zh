"""Run-context construction helpers for incremental crawler runs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from backend.services.crawler.part_registry import resolve_source_parts

from .incremental_fetch_state import utc_now


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
