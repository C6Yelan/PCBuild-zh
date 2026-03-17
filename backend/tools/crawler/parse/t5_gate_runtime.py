"""T5 link consistency gate runtime façade for crawl-parse."""

from __future__ import annotations

import logging

from backend.core.obs_events import log_loki_event
from backend.services.crawler.staging.conventions import get_crawler_env
from backend.tools.crawler.io.artifact_io import read_jsonl_objects
from backend.tools.crawler.link_consistency_check_json import main as run_link_consistency_check_json
from backend.tools.crawler.parse.artifacts import write_t5_input
from backend.tools.crawler.parse.gate_models import T5GateConfig, T5GateOutcome
from backend.tools.crawler.parse.t5_gate_execution_runtime import run_t5_gate_runtime


def run_t5_gate(
    *,
    config: T5GateConfig,
    dq_passed_items: list[dict[str, object]],
    logger: logging.Logger,
) -> T5GateOutcome:
    return run_t5_gate_runtime(
        config=config,
        dq_passed_items=dq_passed_items,
        logger=logger,
        env_value=get_crawler_env(),
        log_event_fn=log_loki_event,
        run_link_check_fn=run_link_consistency_check_json,
        read_reports_fn=read_jsonl_objects,
        write_input_fn=write_t5_input,
    )


__all__ = ["run_t5_gate"]
