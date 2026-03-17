"""Argv builders for crawl-parse and T7 staging CLI wrappers."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID


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

    if t5_outdir is None:
        return argv

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
