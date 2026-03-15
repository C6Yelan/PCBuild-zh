# backend/tools/db/staging_capture.py
"""Crawl-parse invocation helpers for staging from a snapshot directory."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any
from uuid import UUID

from backend.tools.crawler.parse.cli import main as crawl_parse_main
from backend.tools.crawler.io.artifact_io import extract_last_json_object, run_cli_main


@dataclass(frozen=True)
class StageCliSummary:
    result: dict[str, Any] | None
    item_total: int
    item_inserted: int
    item_updated: int
    gate_inserted: int
    gate_updated: int


def build_crawl_parse_argv(
    *,
    source: str,
    snapshot_dir: str,
    run_id: str | UUID,
    dq_outdir: Path,
    t5_outdir: Path | None,
    t5_limit: int,
    t5_min_interval_ms: int,
    t5_timeout_s: float,
    t5_max_redirects: int,
    t5_max_bytes: int,
    t5_block_pattern: list[str],
) -> list[str]:
    argv = [
        "--source",
        source,
        "--snapshot-dir",
        snapshot_dir,
        "--dq-outdir",
        str(dq_outdir),
        "--run-id",
        str(run_id),
    ]

    if t5_outdir is not None:
        argv.extend(
            [
                "--t5-outdir",
                str(t5_outdir),
                "--t5-limit",
                str(t5_limit),
                "--t5-min-interval-ms",
                str(t5_min_interval_ms),
                "--t5-timeout-s",
                str(t5_timeout_s),
                "--t5-max-redirects",
                str(t5_max_redirects),
                "--t5-max-bytes",
                str(t5_max_bytes),
            ]
        )
        for pattern in t5_block_pattern:
            argv.extend(["--t5-block-pattern", pattern])

    return argv


def build_stage_from_snapshot_argv(
    *,
    source: str,
    snapshot_dir: str,
    run_id: str,
    artifact_dir: Path,
    t5_limit: int,
    t5_min_interval_ms: int,
    t5_timeout_s: float,
    t5_max_redirects: int,
    t5_max_bytes: int,
    t5_block_pattern: list[str],
) -> list[str]:
    argv = [
        "--source",
        source,
        "--snapshot-dir",
        snapshot_dir,
        "--run-id",
        str(run_id),
        "--artifact-dir",
        str(artifact_dir),
        "--enable-t5",
        "--t5-limit",
        str(int(t5_limit)),
        "--t5-min-interval-ms",
        str(int(t5_min_interval_ms)),
        "--t5-timeout-s",
        str(float(t5_timeout_s)),
        "--t5-max-redirects",
        str(int(t5_max_redirects)),
        "--t5-max-bytes",
        str(int(t5_max_bytes)),
    ]
    for pattern in t5_block_pattern:
        argv.extend(["--t5-block-pattern", str(pattern)])
    return argv


def run_crawl_parse(argv: list[str]) -> tuple[int, str, str]:
    return run_cli_main(
        crawl_parse_main,
        argv,
        program_name="crawl_parse_snapshot",
    )


def load_pass_items(stdout_txt: str) -> list[dict[str, Any]]:
    if not stdout_txt.strip():
        return []

    parsed = json.loads(stdout_txt)
    if not isinstance(parsed, list):
        raise SystemExit("crawl_parse_snapshot stdout 不是 list JSON，無法入庫")
    return parsed


def load_stage_summary(stdout_txt: str) -> StageCliSummary:
    result = extract_last_json_object(stdout_txt)
    item_inserted = int((result or {}).get("item_inserted") or 0)
    item_updated = int((result or {}).get("item_updated") or 0)
    gate_inserted = int((result or {}).get("gate_inserted") or 0)
    gate_updated = int((result or {}).get("gate_updated") or 0)
    raw_item_total = (result or {}).get("item_total")

    try:
        item_total = int(raw_item_total) if raw_item_total is not None else item_inserted + item_updated
    except (TypeError, ValueError):
        item_total = item_inserted + item_updated

    return StageCliSummary(
        result=result,
        item_total=item_total,
        item_inserted=item_inserted,
        item_updated=item_updated,
        gate_inserted=gate_inserted,
        gate_updated=gate_updated,
    )
