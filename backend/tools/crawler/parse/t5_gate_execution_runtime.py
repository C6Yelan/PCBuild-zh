# backend/tools/crawler/parse/t5_gate_execution_runtime.py
"""Execution helper for the link-consistency gate runtime."""

from __future__ import annotations

import logging
import time
from typing import Any, Callable

from backend.tools.crawler.parse.gate_models import T5GateConfig, T5GateOutcome
from backend.tools.crawler.parse.t5_gate_inputs import (
    build_t5_argv,
    coerce_t5_input_items,
    select_t5_items,
)
from backend.tools.crawler.parse.t5_gate_outcomes import (
    build_t5_command_error_outcome,
    build_t5_input_error_outcome,
    build_t5_length_mismatch_outcome,
    build_t5_output_error_outcome,
    build_t5_success_outcome,
    elapsed_milliseconds,
)
from backend.tools.crawler.parse.t5_gate_reporting import (
    log_t5_started,
)


def run_t5_gate_runtime(
    *,
    config: T5GateConfig,
    dq_passed_items: list[dict[str, Any]],
    logger: logging.Logger,
    env_value: str,
    log_event_fn: Callable[..., None],
    run_link_check_fn: Callable[[list[str]], int],
    read_reports_fn: Callable[[Any], list[dict[str, Any]]],
    write_input_fn: Callable[[Any, list[dict[str, Any]]], None],
) -> T5GateOutcome:
    started = time.monotonic()
    config.artifacts.outdir.mkdir(parents=True, exist_ok=True)

    link_check_items = select_t5_items(passed_items=dq_passed_items, limit=int(config.limit))
    log_t5_started(
        logger,
        log_event_fn=log_event_fn,
        config=config,
        env_value=env_value,
        input_total=len(link_check_items),
    )

    try:
        link_check_input_items = coerce_t5_input_items(link_check_items, source=config.source)
    except ValueError as exc:
        return build_t5_input_error_outcome(
            config=config,
            env_value=env_value,
            error=str(exc),
            exc_type=type(exc).__name__,
            input_total=len(link_check_items),
            logger=logger,
            log_event_fn=log_event_fn,
            elapsed_ms=elapsed_milliseconds(started),
        )

    write_input_fn(config.artifacts, link_check_input_items)

    link_check_rc = run_link_check_fn(build_t5_argv(config))
    if link_check_rc != 0:
        return build_t5_command_error_outcome(
            config=config,
            env_value=env_value,
            t5_rc=int(link_check_rc),
            input_total=len(link_check_items),
            logger=logger,
            log_event_fn=log_event_fn,
            elapsed_ms=elapsed_milliseconds(started),
        )

    try:
        reports = read_reports_fn(config.artifacts.report_path)
    except (OSError, ValueError) as exc:
        return build_t5_output_error_outcome(
            config=config,
            env_value=env_value,
            error=str(exc),
            exc_type=type(exc).__name__,
            input_total=len(link_check_items),
            logger=logger,
            log_event_fn=log_event_fn,
            elapsed_ms=elapsed_milliseconds(started),
        )

    if len(reports) != len(link_check_items):
        return build_t5_length_mismatch_outcome(
            config=config,
            env_value=env_value,
            input_total=len(link_check_items),
            report_total=len(reports),
            logger=logger,
            log_event_fn=log_event_fn,
            elapsed_ms=elapsed_milliseconds(started),
        )

    return build_t5_success_outcome(
        config=config,
        env_value=env_value,
        items=link_check_items,
        reports=reports,
        logger=logger,
        log_event_fn=log_event_fn,
        elapsed_ms=elapsed_milliseconds(started),
    )
