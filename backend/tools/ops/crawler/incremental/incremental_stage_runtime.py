"""Stage execution helpers for incremental crawler runs."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from backend.db import SessionLocal
from backend.services.crawler.fetch_state_repo import get_fetch_state
from backend.tools.db.stage_from_snapshot_cli import main as t7_stage_main
from backend.tools.db.staging_capture import build_stage_from_snapshot_argv, load_stage_summary

from .incremental_fetch_state import record_fetch_state, utc_now
from .incremental_subprocess import run_cli_main, write_text_file


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
