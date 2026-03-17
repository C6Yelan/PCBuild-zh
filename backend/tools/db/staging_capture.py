# backend/tools/db/staging_capture.py
"""Crawl-parse invocation helpers for staging from a snapshot directory."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.tools.crawler.parse.cli import main as crawl_parse_main
from backend.tools.crawler.io.artifact_io import run_cli_main
from backend.tools.db.staging_capture_argv import (
    build_crawl_parse_argv as build_crawl_parse_argv_runtime,
)
from backend.tools.db.staging_capture_argv import (
    build_stage_from_snapshot_argv as build_stage_from_snapshot_argv_runtime,
)
from backend.tools.db.staging_capture_parsing import load_pass_items as load_pass_items_runtime
from backend.tools.db.staging_capture_parsing import parse_stage_summary


@dataclass(frozen=True)
class StageCliSummary:
    result: dict[str, Any] | None
    item_total: int
    item_inserted: int
    item_updated: int
    gate_inserted: int
    gate_updated: int


@dataclass(frozen=True)
class CrawlParseCapture:
    rc: int
    stdout_txt: str
    stderr_txt: str
    items: list[dict[str, Any]]


def build_crawl_parse_argv(**kwargs: Any) -> list[str]:
    return build_crawl_parse_argv_runtime(**kwargs)


def build_stage_from_snapshot_argv(**kwargs: Any) -> list[str]:
    return build_stage_from_snapshot_argv_runtime(**kwargs)


def run_crawl_parse(argv: list[str]) -> tuple[int, str, str]:
    return run_cli_main(
        crawl_parse_main,
        argv,
        program_name="crawl_parse_snapshot",
    )


def run_crawl_parse_capture(argv: list[str]) -> CrawlParseCapture:
    rc, stdout_txt, stderr_txt = run_crawl_parse(argv)
    return CrawlParseCapture(
        rc=int(rc),
        stdout_txt=stdout_txt,
        stderr_txt=stderr_txt,
        items=load_pass_items(stdout_txt),
    )


def load_pass_items(stdout_txt: str) -> list[dict[str, Any]]:
    return load_pass_items_runtime(stdout_txt)


def load_stage_summary(stdout_txt: str) -> StageCliSummary:
    result, item_total, item_inserted, item_updated, gate_inserted, gate_updated = parse_stage_summary(stdout_txt)
    return StageCliSummary(
        result=result,
        item_total=item_total,
        item_inserted=item_inserted,
        item_updated=item_updated,
        gate_inserted=gate_inserted,
        gate_updated=gate_updated,
    )
