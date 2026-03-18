# backend/tools/crawler/parse/t5_gate_reporting.py
"""Logging/reporting helpers for the link-consistency runtime."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Callable

from backend.tools.crawler.parse.gate_models import T5GateConfig


def log_t5_started(
    logger: logging.Logger,
    *,
    log_event_fn: Callable[..., None],
    config: T5GateConfig,
    env_value: str,
    input_total: int,
) -> None:
    log_event_fn(
        logger,
        event="t5_link_started",
        source=config.source,
        stage="t5_link",
        env=env_value,
        gate_name="t5_link",
        run_id=config.run_id,
        app_git_sha=config.app_git_sha,
        snapshot_dir=str(config.snapshot_dir),
        t5_outdir=str(config.artifacts.outdir),
        input_total=int(input_total),
        min_interval_ms=int(config.min_interval_ms),
        timeout_s=float(config.timeout_s),
        max_redirects=int(config.max_redirects),
        max_bytes=int(config.max_bytes),
        started_at=datetime.now(timezone.utc).isoformat(),
    )


def log_t5_failed(
    logger: logging.Logger,
    *,
    log_event_fn: Callable[..., None],
    config: T5GateConfig,
    env_value: str,
    input_total: int,
    elapsed_ms: int,
    error: str,
    exc_type: str,
    t5_rc: int | None = None,
    report_total: int | None = None,
) -> None:
    fields: dict[str, Any] = {
        "event": "t5_link_failed",
        "source": config.source,
        "stage": "t5_link",
        "env": env_value,
        "gate_name": "t5_link",
        "run_id": config.run_id,
        "app_git_sha": config.app_git_sha,
        "snapshot_dir": str(config.snapshot_dir),
        "t5_outdir": str(config.artifacts.outdir),
        "input_total": int(input_total),
        "error": error,
        "exc_type": exc_type,
        "elapsed_ms": int(elapsed_ms),
        "ended_at": datetime.now(timezone.utc).isoformat(),
    }
    if t5_rc is not None:
        fields["t5_rc"] = int(t5_rc)
    if report_total is not None:
        fields["report_total"] = int(report_total)
    log_event_fn(logger, level=logging.ERROR, **fields)


def log_t5_finished(
    logger: logging.Logger,
    *,
    log_event_fn: Callable[..., None],
    config: T5GateConfig,
    env_value: str,
    input_total: int,
    report_total: int,
    matched_total: int,
    non_match_total: int,
    status: str,
    elapsed_ms: int,
) -> None:
    log_event_fn(
        logger,
        event="t5_link_finished",
        source=config.source,
        stage="t5_link",
        env=env_value,
        gate_name="t5_link",
        run_id=config.run_id,
        app_git_sha=config.app_git_sha,
        snapshot_dir=str(config.snapshot_dir),
        t5_outdir=str(config.artifacts.outdir),
        status=status,
        input_total=int(input_total),
        report_total=int(report_total),
        matched_total=int(matched_total),
        non_match_total=int(non_match_total),
        elapsed_ms=int(elapsed_ms),
        ended_at=datetime.now(timezone.utc).isoformat(),
    )
