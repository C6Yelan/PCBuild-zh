# backend/tools/ops/crawler/incremental/incremental_phase_runtime.py
"""Run-level fetch and changed-phase orchestration for incremental crawler runs."""

from __future__ import annotations

from typing import Callable

from backend.db import SessionLocal
from backend.services.crawler import CrawlerHttpClient, CrawlerSettings

from .incremental_execution import (
    run_dry_parse_steps,
    run_merge_and_publish,
    run_stage_steps,
)
from .incremental_fetch import collect_changed_parts
from .incremental_run_state import (
    IncrementalRunContext,
    log_incremental_skip_events,
    set_incremental_skip_summary,
)


def run_incremental_fetch_phase(
    context: IncrementalRunContext,
    *,
    targets: list[tuple[str, object]],
    log_event: Callable[..., None],
) -> tuple[list[dict[str, object]], int]:
    if not targets:
        return [], 0

    with SessionLocal() as db:
        with CrawlerHttpClient(CrawlerSettings()) as client:
            return collect_changed_parts(
                db=db,
                client=client,
                source=context.source,
                run_id=context.run_id,
                run_dir=context.run_dir,
                targets=targets,
                dry_run=context.dry_run,
                summary=context.summary,
                log_event=log_event,
            )


def run_incremental_changed_phases(
    context: IncrementalRunContext,
    *,
    changed_parts: list[dict[str, object]],
    current_rc: int,
    log_event: Callable[..., None],
) -> int:
    rc = int(current_rc)

    if context.dry_run:
        if run_dry_parse_steps(
            args=context.args,
            source=context.source,
            run_id=context.run_id,
            run_dir=context.run_dir,
            changed_parts=changed_parts,
            summary=context.summary,
            log_event=log_event,
        ):
            rc = 2

        set_incremental_skip_summary(
            context.summary,
            merge_rc=0 if rc == 0 else None,
            publish_rc=0 if rc == 0 else None,
            reason="skipped_dry_run",
            published=False,
        )
        log_incremental_skip_events(
            log_event=log_event,
            source=context.source,
            run_id=context.run_id,
            rc=0 if rc == 0 else 2,
            reason="dry_run",
            changed_part_total=len(changed_parts),
            published=False,
        )
        return rc

    if run_stage_steps(
        args=context.args,
        source=context.source,
        run_id=context.run_id,
        run_dir=context.run_dir,
        dry_run=context.dry_run,
        changed_parts=changed_parts,
        summary=context.summary,
        log_event=log_event,
    ):
        rc = 2

    if rc == 0:
        if run_merge_and_publish(
            source=context.source,
            run_id=context.run_id,
            run_dir=context.run_dir,
            changed_parts=changed_parts,
            publish_enabled=context.publish_enabled,
            summary=context.summary,
            log_event=log_event,
        ):
            rc = 2
        return rc

    set_incremental_skip_summary(
        context.summary,
        merge_rc=None,
        publish_rc=None,
        reason="skipped_due_to_stage_errors",
        published=False,
    )
    context.summary["publish"] = {"rc": None, "published": False, "reason": "skipped_due_to_errors"}
    return rc


__all__ = [
    "run_incremental_changed_phases",
    "run_incremental_fetch_phase",
]
