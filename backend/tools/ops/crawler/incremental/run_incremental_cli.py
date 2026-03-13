# backend/tools/ops/crawler/run_incremental_cli.py
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any
from uuid import uuid4

from backend.core.obs_events import ensure_cli_logging, log_loki_event
from backend.db import SessionLocal
from backend.services.crawler import CrawlerHttpClient, CrawlerSettings
from backend.services.crawler.part_registry import resolve_source_parts
from backend.services.crawler.staging.conventions import get_crawler_env
from backend.tools.crawler.io.artifact_io import write_json_file
from .incremental_cli import incremental_cli_options_from_namespace
from .incremental_execution import (
    run_dry_parse_steps,
    run_merge_and_publish,
    run_stage_steps,
)
from .incremental_fetch import collect_changed_parts, utc_now

_PIPELINE_LOGGER = logging.getLogger("pcbuild.pipeline")


def _build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="T10: run incremental refresh (fetch -> parse/gates -> stage -> merge -> publish)"
    )
    ap.add_argument("--source", required=True, help="crawler source id, e.g. coolpc")
    ap.add_argument("--parts", default="all", help="comma-separated part list, default: all")
    ap.add_argument("--dry-run", action="store_true", help="do not write DB and do not publish")

    pub_group = ap.add_mutually_exclusive_group()
    pub_group.add_argument("--publish", dest="publish", action="store_true", help="publish to pointer after merge")
    pub_group.add_argument("--no-publish", dest="publish", action="store_false", help="skip publish (default)")
    ap.set_defaults(publish=False)

    ap.add_argument("--max-items", type=int, default=0, help="per-part protection cap; <=0 means unlimited")
    ap.add_argument("--t5-limit", type=int, default=0, help="T5 check first N rows; <=0 means full")
    ap.add_argument("--t5-min-interval-ms", type=int, default=1500)
    ap.add_argument("--t5-timeout-s", type=float, default=10.0)
    ap.add_argument("--t5-max-redirects", type=int, default=5)
    ap.add_argument("--t5-max-bytes", type=int, default=4194304)
    ap.add_argument("--t5-block-pattern", action="append", default=[])
    return ap


def _log_event(
    *,
    event: str,
    source: str,
    stage: str,
    run_id: str,
    part_type: str | None = None,
    **fields: Any,
) -> None:
    extra = dict(fields)
    if part_type is not None:
        extra["part_type"] = part_type
    log_loki_event(
        _PIPELINE_LOGGER,
        event=event,
        source=source,
        stage=stage,
        env=get_crawler_env(),
        run_id=run_id,
        **extra,
    )


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    options = incremental_cli_options_from_namespace(args)
    if int(options.max_items) < 0:
        raise SystemExit("--max-items must be >= 0")

    # Keep this module path stable for existing SOP/CLI usage; detailed steps live in sibling helpers.
    src = options.source
    dry_run = options.dry_run
    publish_requested = options.publish
    publish_enabled = bool(options.publish and not dry_run)

    ensure_cli_logging(logger=_PIPELINE_LOGGER)

    run_id = str(uuid4())
    run_dir = (Path("temp") / "t10" / run_id).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    summary_path = run_dir / "summary.json"

    started_at = utc_now()
    summary: dict[str, Any] = {
        "run_id": run_id,
        "source": src,
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

    rc = 0

    try:
        try:
            targets = resolve_source_parts(src, options.parts)
            summary["parts_requested"] = [p for p, _ in targets]
            summary["counts"]["parts_total"] = len(targets)
        except Exception as e:
            summary["errors"].append(f"resolve_parts_failed: {e}")
            targets = []
            rc = 2

        if publish_requested and dry_run:
            summary["errors"].append("publish_ignored_in_dry_run")

        _log_event(
            event="t10_start",
            source=src,
            stage="incremental",
            run_id=run_id,
            part_total=int(summary["counts"]["parts_total"]),
            dry_run=dry_run,
            publish_enabled=publish_enabled,
            max_items=int(options.max_items),
            requested_parts=summary["parts_requested"],
        )

        changed_parts: list[dict[str, Any]] = []

        if targets:
            with SessionLocal() as db:
                with CrawlerHttpClient(CrawlerSettings()) as client:
                    changed_parts, fetch_rc = collect_changed_parts(
                        db=db,
                        client=client,
                        source=src,
                        run_id=run_id,
                        run_dir=run_dir,
                        targets=targets,
                        dry_run=dry_run,
                        summary=summary,
                        log_event=_log_event,
                    )
            if fetch_rc != 0:
                rc = 2

        if changed_parts:
            if dry_run:
                if run_dry_parse_steps(
                    args=args,
                    source=src,
                    run_id=run_id,
                    run_dir=run_dir,
                    changed_parts=changed_parts,
                    summary=summary,
                    log_event=_log_event,
                ):
                    rc = 2

                summary["merge"] = {"rc": 0 if rc == 0 else None, "reason": "skipped_dry_run"}
                summary["publish"] = {
                    "rc": 0 if rc == 0 else None,
                    "published": False,
                    "reason": "skipped_dry_run",
                }
                _log_event(
                    event="t10_merge_done",
                    source=src,
                    stage="merge",
                    run_id=run_id,
                    part_type="all",
                    rc=0 if rc == 0 else 2,
                    changed_part_total=int(len(changed_parts)),
                    skipped=True,
                    reason="dry_run",
                )
                _log_event(
                    event="t10_publish_done",
                    source=src,
                    stage="publish",
                    run_id=run_id,
                    part_type="all",
                    rc=0 if rc == 0 else 2,
                    published=False,
                    reason="dry_run",
                )
            else:
                if run_stage_steps(
                    args=args,
                    source=src,
                    run_id=run_id,
                    run_dir=run_dir,
                    dry_run=dry_run,
                    changed_parts=changed_parts,
                    summary=summary,
                    log_event=_log_event,
                ):
                    rc = 2

                if rc == 0:
                    if run_merge_and_publish(
                        source=src,
                        run_id=run_id,
                        run_dir=run_dir,
                        changed_parts=changed_parts,
                        publish_enabled=publish_enabled,
                        summary=summary,
                        log_event=_log_event,
                    ):
                        rc = 2
                else:
                    summary["merge"] = {"rc": None, "reason": "skipped_due_to_stage_errors"}
                    summary["publish"] = {"rc": None, "published": False, "reason": "skipped_due_to_errors"}
        else:
            skip_reason = "skipped_no_changed_parts" if rc == 0 else "skipped_due_to_errors"
            skip_rc = 0 if rc == 0 else 2
            summary["merge"] = {"rc": skip_rc, "reason": skip_reason}
            summary["publish"] = {"rc": skip_rc, "published": False, "reason": skip_reason}
            _log_event(
                event="t10_merge_done",
                source=src,
                stage="merge",
                run_id=run_id,
                part_type="all",
                rc=skip_rc,
                changed_part_total=0,
                skipped=True,
                reason=skip_reason,
            )
            _log_event(
                event="t10_publish_done",
                source=src,
                stage="publish",
                run_id=run_id,
                part_type="all",
                rc=skip_rc,
                published=False,
                reason=skip_reason,
            )
    except Exception as e:
        summary["errors"].append(f"unhandled_error: {e}")
        summary["errors"].append(f"exc_type: {type(e).__name__}")
        if summary["merge"] is None:
            summary["merge"] = {"rc": None, "reason": "skipped_due_to_errors"}
        if summary["publish"] is None:
            summary["publish"] = {"rc": None, "published": False, "reason": "skipped_due_to_errors"}
        rc = 2

    ended_at = utc_now()
    summary["ended_at"] = ended_at.isoformat()
    summary["elapsed_ms"] = int((ended_at - started_at).total_seconds() * 1000)
    summary["exit_code"] = int(rc)
    write_json_file(summary_path, summary)

    print(
        json.dumps(
            {
                "run_id": run_id,
                "summary_path": str(summary_path),
                "exit_code": int(rc),
                "changed_parts": int(summary["counts"]["parts_changed"]),
                "no_change_parts": int(summary["counts"]["parts_no_change"]),
            },
            ensure_ascii=False,
        )
    )
    return int(rc)


if __name__ == "__main__":
    raise SystemExit(main())
