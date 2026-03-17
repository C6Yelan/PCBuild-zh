# backend/tools/crawler/parse/t5_gate_outcomes.py
"""Outcome builders for the T5 link-consistency runtime."""

from __future__ import annotations

import logging
import time
from typing import Any, Callable

from backend.tools.crawler.parse.gate_models import T5GateConfig, T5GateOutcome
from backend.tools.crawler.parse.t5_gate_inputs import build_t5_summary, partition_t5_items
from backend.tools.crawler.parse.t5_gate_reporting import log_t5_failed, log_t5_finished


def build_t5_input_error_outcome(
    *,
    config: T5GateConfig,
    env_value: str,
    error: str,
    exc_type: str,
    input_total: int,
    logger: logging.Logger,
    log_event_fn: Callable[..., None],
    elapsed_ms: int,
) -> T5GateOutcome:
    log_t5_failed(
        logger,
        log_event_fn=log_event_fn,
        config=config,
        env_value=env_value,
        input_total=input_total,
        error=error,
        exc_type=exc_type,
        elapsed_ms=elapsed_ms,
    )
    return T5GateOutcome(
        rc=2,
        summary=None,
        passed_items=[],
        quarantined_items=[],
        error_message=f"T5 input error: {error}",
    )


def build_t5_command_error_outcome(
    *,
    config: T5GateConfig,
    env_value: str,
    t5_rc: int,
    input_total: int,
    logger: logging.Logger,
    log_event_fn: Callable[..., None],
    elapsed_ms: int,
) -> T5GateOutcome:
    log_t5_failed(
        logger,
        log_event_fn=log_event_fn,
        config=config,
        env_value=env_value,
        input_total=input_total,
        error=f"link_consistency_check_json failed rc={t5_rc}",
        exc_type="SystemExit",
        t5_rc=t5_rc,
        elapsed_ms=elapsed_ms,
    )
    return T5GateOutcome(
        rc=2,
        summary=None,
        passed_items=[],
        quarantined_items=[],
        error_message=None,
    )


def build_t5_output_error_outcome(
    *,
    config: T5GateConfig,
    env_value: str,
    error: str,
    exc_type: str,
    input_total: int,
    logger: logging.Logger,
    log_event_fn: Callable[..., None],
    elapsed_ms: int,
) -> T5GateOutcome:
    log_t5_failed(
        logger,
        log_event_fn=log_event_fn,
        config=config,
        env_value=env_value,
        input_total=input_total,
        error=error,
        exc_type=exc_type,
        elapsed_ms=elapsed_ms,
    )
    return T5GateOutcome(
        rc=2,
        summary=None,
        passed_items=[],
        quarantined_items=[],
        error_message=f"T5 output error: {error}",
    )


def build_t5_length_mismatch_outcome(
    *,
    config: T5GateConfig,
    env_value: str,
    input_total: int,
    report_total: int,
    logger: logging.Logger,
    log_event_fn: Callable[..., None],
    elapsed_ms: int,
) -> T5GateOutcome:
    message = "T5 output error: report/input length mismatch report=%d input=%d" % (report_total, input_total)
    log_t5_failed(
        logger,
        log_event_fn=log_event_fn,
        config=config,
        env_value=env_value,
        input_total=input_total,
        report_total=report_total,
        error=message,
        exc_type="ValueError",
        elapsed_ms=elapsed_ms,
    )
    return T5GateOutcome(
        rc=2,
        summary=None,
        passed_items=[],
        quarantined_items=[],
        error_message=message,
    )


def build_t5_success_outcome(
    *,
    config: T5GateConfig,
    env_value: str,
    items: list[dict[str, Any]],
    reports: list[dict[str, Any]],
    logger: logging.Logger,
    log_event_fn: Callable[..., None],
    elapsed_ms: int,
) -> T5GateOutcome:
    t5_passed, t5_quarantine = partition_t5_items(items, reports)
    summary = build_t5_summary(reports)
    non_match = int(summary["non_match"])
    log_t5_finished(
        logger,
        log_event_fn=log_event_fn,
        config=config,
        env_value=env_value,
        input_total=len(items),
        report_total=len(reports),
        matched_total=len(t5_passed),
        non_match_total=non_match,
        status="succeeded" if non_match == 0 else "completed_with_mismatch",
        elapsed_ms=elapsed_ms,
    )
    return T5GateOutcome(
        rc=0 if non_match == 0 else 2,
        summary=summary,
        passed_items=t5_passed,
        quarantined_items=t5_quarantine,
        error_message=None,
    )


def elapsed_milliseconds(started_monotonic: float) -> int:
    return int((time.monotonic() - started_monotonic) * 1000)
