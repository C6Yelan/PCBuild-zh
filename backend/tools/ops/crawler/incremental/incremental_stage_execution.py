"""Parse and stage execution helpers for incremental crawler runs."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from backend.db import SessionLocal
from backend.services.crawler.fetch_state_repo import get_fetch_state
from backend.tools.crawler.parse.cli import main as crawl_parse_main
from backend.tools.db.stage_from_snapshot_cli import main as t7_stage_main
from backend.tools.db.staging_capture import (
    build_crawl_parse_argv,
    build_stage_from_snapshot_argv,
    load_stage_summary,
)

from .incremental_fetch import record_fetch_state, utc_now
from .incremental_parsing import extract_json_array
from .incremental_subprocess import run_cli_main, write_text_file


def run_dry_parse_steps(
    *,
    args: Any,
    source: str,
    run_id: str,
    run_dir: Path,
    changed_parts: list[dict[str, Any]],
    summary: dict[str, Any],
    log_event: Callable[..., None],
) -> int:
    rc = 0

    for part in changed_parts:
        part_type = str(part["part_type"])
        snapshot_dir = str(part["snapshot_dir"])
        part_entry = part["entry_ref"]
        part_logs = run_dir / "parts" / part_type / "logs"

        parse_argv = build_crawl_parse_argv(
            source=source,
            snapshot_dir=snapshot_dir,
            run_id=run_id,
            dq_outdir=run_dir / "parts" / part_type / "dq",
            t5_outdir=None,
            t5_limit=0,
            t5_min_interval_ms=0,
            t5_timeout_s=0.0,
            t5_max_redirects=0,
            t5_max_bytes=0,
            t5_block_pattern=[],
        )
        parse_rc, parse_stdout, parse_stderr = run_cli_main(crawl_parse_main, parse_argv)
        write_text_file(part_logs / "parse.stdout.log", parse_stdout)
        write_text_file(part_logs / "parse.stderr.log", parse_stderr)

        parsed_items = extract_json_array(parse_stdout)
        item_total = int(len(parsed_items)) if isinstance(parsed_items, list) else 0
        over_limit = bool(args.max_items > 0 and item_total > int(args.max_items))

        part_entry["parse"] = {
            "rc": int(parse_rc),
            "item_total": item_total,
            "over_limit": over_limit,
            "stdout_log": str(part_logs / "parse.stdout.log"),
            "stderr_log": str(part_logs / "parse.stderr.log"),
        }

        log_event(
            event="t10_parse_done",
            source=source,
            stage="parse",
            run_id=run_id,
            part_type=part_type,
            rc=int(parse_rc),
            item_total=item_total,
            over_limit=over_limit,
        )

        if parse_rc != 0 or over_limit:
            part_entry["status"] = "parse_failed"
            summary["counts"]["parts_failed"] += 1
            if over_limit:
                summary["errors"].append(
                    f"max_items_exceeded[{part_type}]: item_total={item_total} max_items={args.max_items}"
                )
            else:
                summary["errors"].append(f"parse_failed[{part_type}]: rc={parse_rc}")
            rc = 2
        else:
            part_entry["status"] = "parsed"

    return rc


def run_stage_steps(
    *,
    args: Any,
    source: str,
    run_id: str,
    run_dir: Path,
    dry_run: bool,
    changed_parts: list[dict[str, Any]],
    summary: dict[str, Any],
    log_event: Callable[..., None],
) -> int:
    rc = 0

    with SessionLocal() as db:
        for part in changed_parts:
            part_type = str(part["part_type"])
            snapshot_dir = str(part["snapshot_dir"])
            part_entry = part["entry_ref"]
            part_logs = run_dir / "parts" / part_type / "logs"
            part_t7_artifact_dir = run_dir / "parts" / part_type / "t7_artifacts"

            stage_argv = build_stage_from_snapshot_argv(
                source=source,
                snapshot_dir=snapshot_dir,
                run_id=run_id,
                artifact_dir=part_t7_artifact_dir,
                t5_limit=int(args.t5_limit),
                t5_min_interval_ms=int(args.t5_min_interval_ms),
                t5_timeout_s=float(args.t5_timeout_s),
                t5_max_redirects=int(args.t5_max_redirects),
                t5_max_bytes=int(args.t5_max_bytes),
                t5_block_pattern=[str(value) for value in args.t5_block_pattern],
            )
            stage_rc, stage_stdout, stage_stderr = run_cli_main(t7_stage_main, stage_argv)
            write_text_file(part_logs / "stage.stdout.log", stage_stdout)
            write_text_file(part_logs / "stage.stderr.log", stage_stderr)

            stage_summary = load_stage_summary(stage_stdout)
            stage_obj = stage_summary.result
            staged_total = int(stage_summary.item_total)
            over_limit = bool(args.max_items > 0 and staged_total > int(args.max_items))

            part_entry["parse"] = {
                "rc": int(stage_rc),
                "item_total": staged_total,
                "over_limit": over_limit,
                "note": "t7 stage includes parse/gates before DB write",
            }
            part_entry["stage"] = {
                "rc": int(stage_rc),
                "result": stage_obj,
                "over_limit": over_limit,
                "artifact_dir": str(part_t7_artifact_dir),
                "stdout_log": str(part_logs / "stage.stdout.log"),
                "stderr_log": str(part_logs / "stage.stderr.log"),
            }

            log_event(
                event="t10_parse_done",
                source=source,
                stage="parse",
                run_id=run_id,
                part_type=part_type,
                rc=int(stage_rc),
                item_total=staged_total,
                over_limit=over_limit,
            )
            log_event(
                event="t10_stage_done",
                source=source,
                stage="stage",
                run_id=run_id,
                part_type=part_type,
                rc=int(stage_rc),
                item_total=staged_total,
                item_inserted=int(stage_summary.item_inserted),
                item_updated=int(stage_summary.item_updated),
                gate_inserted=int(stage_summary.gate_inserted),
                gate_updated=int(stage_summary.gate_updated),
            )

            if stage_rc != 0 or over_limit:
                part_entry["status"] = "stage_failed"
                summary["counts"]["parts_failed"] += 1
                if over_limit:
                    summary["errors"].append(
                        f"max_items_exceeded[{part_type}]: item_total={staged_total} max_items={args.max_items}"
                    )
                else:
                    summary["errors"].append(f"stage_failed[{part_type}]: rc={stage_rc}")
                rc = 2
                continue

            part_entry["status"] = "staged"
            stage_state = get_fetch_state(
                db,
                source=source,
                part_type=part_type,
                url=str(part["url"]),
            )
            record_fetch_state(
                db,
                dry_run=dry_run,
                source=source,
                part_type=part_type,
                url=str(part["url"]),
                etag=stage_state.etag if stage_state is not None else None,
                last_modified=stage_state.last_modified if stage_state is not None else None,
                content_sha256=stage_state.content_sha256 if stage_state is not None else None,
                last_status_code=stage_state.last_status_code if stage_state is not None else None,
                last_success_at=utc_now(),
            )

    return rc


__all__ = [
    "run_dry_parse_steps",
    "run_stage_steps",
]
