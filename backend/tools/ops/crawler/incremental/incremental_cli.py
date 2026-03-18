# backend/tools/ops/crawler/incremental/incremental_cli.py
"""Shared incremental CLI option payload and argv builder for incremental crawler tools."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class IncrementalCliOptions:
    source: str
    parts: str
    dry_run: bool
    publish: bool
    max_items: int
    t5_limit: int
    t5_min_interval_ms: int
    t5_timeout_s: float
    t5_max_redirects: int
    t5_max_bytes: int
    t5_block_pattern: tuple[str, ...]


def build_incremental_cli_options(
    *,
    source: Any,
    parts: Any,
    dry_run: Any,
    publish: Any,
    max_items: Any,
    t5_limit: Any,
    t5_min_interval_ms: Any,
    t5_timeout_s: Any,
    t5_max_redirects: Any,
    t5_max_bytes: Any,
    t5_block_pattern: Any,
) -> IncrementalCliOptions:
    return IncrementalCliOptions(
        source=str(source).strip().lower(),
        parts=str(parts).strip() or "all",
        dry_run=bool(dry_run),
        publish=bool(publish),
        max_items=int(max_items),
        t5_limit=int(t5_limit),
        t5_min_interval_ms=int(t5_min_interval_ms),
        t5_timeout_s=float(t5_timeout_s),
        t5_max_redirects=int(t5_max_redirects),
        t5_max_bytes=int(t5_max_bytes),
        t5_block_pattern=tuple(str(value) for value in (t5_block_pattern or [])),
    )


def incremental_cli_options_from_namespace(args: Any) -> IncrementalCliOptions:
    return build_incremental_cli_options(
        source=getattr(args, "source"),
        parts=getattr(args, "parts"),
        dry_run=getattr(args, "dry_run"),
        publish=getattr(args, "publish"),
        max_items=getattr(args, "max_items"),
        t5_limit=getattr(args, "t5_limit"),
        t5_min_interval_ms=getattr(args, "t5_min_interval_ms"),
        t5_timeout_s=getattr(args, "t5_timeout_s"),
        t5_max_redirects=getattr(args, "t5_max_redirects"),
        t5_max_bytes=getattr(args, "t5_max_bytes"),
        t5_block_pattern=getattr(args, "t5_block_pattern"),
    )


def build_incremental_argv(options: IncrementalCliOptions) -> list[str]:
    argv = [
        "--source",
        options.source,
        "--parts",
        options.parts,
        "--max-items",
        str(int(options.max_items)),
        "--t5-limit",
        str(int(options.t5_limit)),
        "--t5-min-interval-ms",
        str(int(options.t5_min_interval_ms)),
        "--t5-timeout-s",
        str(float(options.t5_timeout_s)),
        "--t5-max-redirects",
        str(int(options.t5_max_redirects)),
        "--t5-max-bytes",
        str(int(options.t5_max_bytes)),
    ]
    for value in options.t5_block_pattern:
        argv.extend(["--t5-block-pattern", str(value)])
    if options.dry_run:
        argv.append("--dry-run")
    argv.append("--publish" if options.publish else "--no-publish")
    return argv
