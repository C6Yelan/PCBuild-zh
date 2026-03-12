# backend/tools/ops/incremental_execution.py
"""Execution helpers for parse, stage, merge, and publish incremental steps."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from backend.db import SessionLocal
from backend.services.crawler.fetch_state_repo import get_fetch_state
from backend.tools.crawler.crawl_parse_snapshot import main as crawl_parse_main
from backend.tools.db.t7_stage_from_snapshot import main as t7_stage_main
from backend.tools.db.t8_merge_from_staging import main as t8_merge_main
from backend.tools.ops.crawler.incremental_fetch import record_fetch_state, utc_now
from backend.tools.ops.crawler.incremental_parsing import (
    extract_json_array,
    extract_last_json_object,
    parse_t8_counts,
)
from backend.tools.ops.crawler.incremental_subprocess import run_cli_main, write_text_file
from backend.tools.ops.crawler.t9_publish_publication import main as t9_publish_main


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

        parse_argv = [
            "--source",
            source,
            "--snapshot-dir",
            snapshot_dir,
            "--run-id",
            run_id,
            "--dq-outdir",
            str(run_dir / "parts" / part_type / "dq"),
        ]
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

            stage_argv = [
                "--source",
                source,
                "--snapshot-dir",
                snapshot_dir,
                "--run-id",
                run_id,
                "--artifact-dir",
                str(part_t7_artifact_dir),
                "--enable-t5",
                "--t5-limit",
                str(int(args.t5_limit)),
                "--t5-min-interval-ms",
                str(int(args.t5_min_interval_ms)),
                "--t5-timeout-s",
                str(float(args.t5_timeout_s)),
                "--t5-max-redirects",
                str(int(args.t5_max_redirects)),
                "--t5-max-bytes",
                str(int(args.t5_max_bytes)),
            ]
            for value in args.t5_block_pattern:
                stage_argv.extend(["--t5-block-pattern", str(value)])
            stage_rc, stage_stdout, stage_stderr = run_cli_main(t7_stage_main, stage_argv)
            write_text_file(part_logs / "stage.stdout.log", stage_stdout)
            write_text_file(part_logs / "stage.stderr.log", stage_stderr)

            stage_obj = extract_last_json_object(stage_stdout)
            staged_total: int | None = None
            if isinstance(stage_obj, dict):
                raw_item_total = stage_obj.get("item_total")
                if raw_item_total is not None:
                    try:
                        staged_total = int(raw_item_total)
                    except (TypeError, ValueError):
                        staged_total = None

            if staged_total is None:
                staged_total = int((stage_obj or {}).get("item_inserted") or 0) + int(
                    (stage_obj or {}).get("item_updated") or 0
                )

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
                item_inserted=int((stage_obj or {}).get("item_inserted") or 0),
                item_updated=int((stage_obj or {}).get("item_updated") or 0),
                gate_inserted=int((stage_obj or {}).get("gate_inserted") or 0),
                gate_updated=int((stage_obj or {}).get("gate_updated") or 0),
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


def run_merge_and_publish(
    *,
    source: str,
    run_id: str,
    run_dir: Path,
    changed_parts: list[dict[str, Any]],
    publish_enabled: bool,
    summary: dict[str, Any],
    log_event: Callable[..., None],
) -> int:
    merge_argv = ["--run-id", run_id]
    merge_rc, merge_stdout, merge_stderr = run_cli_main(t8_merge_main, merge_argv)
    merge_logs = run_dir / "logs"
    write_text_file(merge_logs / "t8_merge.stdout.log", merge_stdout)
    write_text_file(merge_logs / "t8_merge.stderr.log", merge_stderr)
    merge_counts = parse_t8_counts(merge_stdout + "\n" + merge_stderr) or {}
    summary["merge"] = {
        "rc": int(merge_rc),
        "counts": merge_counts,
        "stdout_log": str(merge_logs / "t8_merge.stdout.log"),
        "stderr_log": str(merge_logs / "t8_merge.stderr.log"),
    }

    log_event(
        event="t10_merge_done",
        source=source,
        stage="merge",
        run_id=run_id,
        part_type="all",
        rc=int(merge_rc),
        changed_part_total=int(len(changed_parts)),
        **merge_counts,
    )

    if merge_rc != 0:
        summary["errors"].append(f"merge_failed: rc={merge_rc}")
        return 2

    if not publish_enabled:
        summary["publish"] = {"rc": 0, "published": False, "reason": "publish_disabled"}
        log_event(
            event="t10_publish_done",
            source=source,
            stage="publish",
            run_id=run_id,
            part_type="all",
            rc=0,
            published=False,
            reason="publish_disabled",
        )
        return 0

    pub_argv = ["--run-id", run_id]
    pub_rc, pub_stdout, pub_stderr = run_cli_main(t9_publish_main, pub_argv)
    write_text_file(merge_logs / "t9_publish.stdout.log", pub_stdout)
    write_text_file(merge_logs / "t9_publish.stderr.log", pub_stderr)
    pub_obj = extract_last_json_object(pub_stdout) or {}

    summary["publish"] = {
        "rc": int(pub_rc),
        "published": bool(pub_obj.get("published") or pub_obj.get("ok")),
        "stdout_log": str(merge_logs / "t9_publish.stdout.log"),
        "stderr_log": str(merge_logs / "t9_publish.stderr.log"),
        "result": pub_obj,
    }

    log_event(
        event="t10_publish_done",
        source=source,
        stage="publish",
        run_id=run_id,
        part_type="all",
        rc=int(pub_rc),
        published=bool(pub_obj.get("published") or pub_obj.get("ok")),
    )

    if pub_rc != 0:
        summary["errors"].append(f"publish_failed: rc={pub_rc}")
        return 2
    return 0
