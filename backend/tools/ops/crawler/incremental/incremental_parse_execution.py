"""Dry-run parse helpers for incremental crawler runs."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from backend.tools.crawler.parse.cli import main as crawl_parse_main
from backend.tools.db.staging_capture import build_crawl_parse_argv

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
