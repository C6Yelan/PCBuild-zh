"""T5 link consistency gate runtime helpers for crawl-parse."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import logging
import time
from typing import Any

from backend.core.obs_events import log_loki_event
from backend.services.crawler.staging.conventions import get_crawler_env
from backend.tools.crawler.io.artifact_io import read_jsonl_objects
from backend.tools.crawler.link_consistency_check_json import main as run_link_consistency_check_json
from backend.tools.crawler.parse.artifacts import write_t5_input
from backend.tools.crawler.parse.gate_models import T5GateConfig, T5GateOutcome


def _build_t5_summary(reports: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts = Counter(str(rep.get("status", "")) for rep in reports)
    reason_counts = Counter(str(rep.get("reason_code", "")) for rep in reports)
    non_match = sum(1 for rep in reports if rep.get("status") != "match")
    return {
        "total": len(reports),
        "non_match": non_match,
        "status_counts": dict(sorted(status_counts.items())),
        "reason_counts": dict(sorted(reason_counts.items())),
    }


def _coerce_t5_input_item(item: Any, *, source: str) -> dict[str, Any]:
    if isinstance(item, dict):
        out = dict(item)
    elif hasattr(item, "model_dump") and callable(getattr(item, "model_dump")):
        dumped = item.model_dump()
        if not isinstance(dumped, dict):
            raise ValueError(f"T5 item model_dump() must return dict, got {type(dumped).__name__}")
        out = dict(dumped)
    elif hasattr(item, "__dict__"):
        out = dict(vars(item))
    else:
        raise ValueError(f"T5 item must be dict-like, got {type(item).__name__}")

    if "source" not in out:
        out["source"] = source
    return out


def _select_t5_items(*, passed_items: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    if limit > 0:
        return passed_items[:limit]
    return passed_items


def _build_t5_argv(config: T5GateConfig) -> list[str]:
    argv = [
        "--input",
        str(config.artifacts.input_path),
        "--output",
        str(config.artifacts.report_path),
        "--min-interval-ms",
        str(config.min_interval_ms),
        "--timeout-s",
        str(config.timeout_s),
        "--max-redirects",
        str(config.max_redirects),
        "--max-bytes",
        str(config.max_bytes),
    ]
    for pattern in config.block_patterns:
        argv.extend(["--block-pattern", pattern])
    return argv


def _log_t5_started(
    logger: logging.Logger,
    *,
    config: T5GateConfig,
    input_total: int,
) -> None:
    log_loki_event(
        logger,
        event="t5_link_started",
        source=config.source,
        stage="t5_link",
        env=get_crawler_env(),
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


def _log_t5_failed(
    logger: logging.Logger,
    *,
    config: T5GateConfig,
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
        "env": get_crawler_env(),
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
    log_loki_event(logger, level=logging.ERROR, **fields)


def _log_t5_finished(
    logger: logging.Logger,
    *,
    config: T5GateConfig,
    input_total: int,
    report_total: int,
    matched_total: int,
    non_match_total: int,
    status: str,
    elapsed_ms: int,
) -> None:
    log_loki_event(
        logger,
        event="t5_link_finished",
        source=config.source,
        stage="t5_link",
        env=get_crawler_env(),
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


def run_t5_gate(
    *,
    config: T5GateConfig,
    dq_passed_items: list[dict[str, Any]],
    logger: logging.Logger,
) -> T5GateOutcome:
    started = time.monotonic()
    config.artifacts.outdir.mkdir(parents=True, exist_ok=True)

    t5_items = _select_t5_items(passed_items=dq_passed_items, limit=int(config.limit))
    _log_t5_started(logger, config=config, input_total=len(t5_items))

    try:
        t5_input_items = [_coerce_t5_input_item(item, source=config.source) for item in t5_items]
    except ValueError as exc:
        _log_t5_failed(
            logger,
            config=config,
            input_total=len(t5_items),
            error=str(exc),
            exc_type=type(exc).__name__,
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
        return T5GateOutcome(
            rc=2,
            summary=None,
            passed_items=[],
            quarantined_items=[],
            error_message=f"T5 input error: {exc}",
        )

    write_t5_input(config.artifacts, t5_input_items)

    t5_rc = run_link_consistency_check_json(_build_t5_argv(config))
    if t5_rc != 0:
        _log_t5_failed(
            logger,
            config=config,
            input_total=len(t5_items),
            error=f"link_consistency_check_json failed rc={t5_rc}",
            exc_type="SystemExit",
            t5_rc=int(t5_rc),
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
        return T5GateOutcome(
            rc=2,
            summary=None,
            passed_items=[],
            quarantined_items=[],
            error_message=None,
        )

    try:
        reports = read_jsonl_objects(config.artifacts.report_path)
    except (OSError, ValueError) as exc:
        _log_t5_failed(
            logger,
            config=config,
            input_total=len(t5_items),
            error=str(exc),
            exc_type=type(exc).__name__,
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
        return T5GateOutcome(
            rc=2,
            summary=None,
            passed_items=[],
            quarantined_items=[],
            error_message=f"T5 output error: {exc}",
        )

    if len(reports) != len(t5_items):
        message = "T5 output error: report/input length mismatch report=%d input=%d" % (len(reports), len(t5_items))
        _log_t5_failed(
            logger,
            config=config,
            input_total=len(t5_items),
            report_total=len(reports),
            error=message,
            exc_type="ValueError",
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
        return T5GateOutcome(
            rc=2,
            summary=None,
            passed_items=[],
            quarantined_items=[],
            error_message=message,
        )

    t5_passed: list[dict[str, Any]] = []
    t5_quarantine: list[dict[str, Any]] = []
    for item, report in zip(t5_items, reports):
        if report.get("status") == "match":
            t5_passed.append(item)
        else:
            t5_quarantine.append(item)

    summary = _build_t5_summary(reports)
    non_match = int(summary["non_match"])
    _log_t5_finished(
        logger,
        config=config,
        input_total=len(t5_items),
        report_total=len(reports),
        matched_total=len(t5_passed),
        non_match_total=non_match,
        status="succeeded" if non_match == 0 else "completed_with_mismatch",
        elapsed_ms=int((time.monotonic() - started) * 1000),
    )

    return T5GateOutcome(
        rc=0 if non_match == 0 else 2,
        summary=summary,
        passed_items=t5_passed,
        quarantined_items=t5_quarantine,
        error_message=None,
    )


__all__ = ["run_t5_gate"]
