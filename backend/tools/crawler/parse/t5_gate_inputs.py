"""Input coercion and argv helpers for the T5 link-consistency runtime."""

from __future__ import annotations

from collections import Counter
from typing import Any

from backend.tools.crawler.parse.gate_models import T5GateConfig


def build_t5_summary(reports: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts = Counter(str(rep.get("status", "")) for rep in reports)
    reason_counts = Counter(str(rep.get("reason_code", "")) for rep in reports)
    non_match = sum(1 for rep in reports if rep.get("status") != "match")
    return {
        "total": len(reports),
        "non_match": non_match,
        "status_counts": dict(sorted(status_counts.items())),
        "reason_counts": dict(sorted(reason_counts.items())),
    }


def coerce_t5_input_item(item: Any, *, source: str) -> dict[str, Any]:
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


def coerce_t5_input_items(
    items: list[dict[str, Any]],
    *,
    source: str,
) -> list[dict[str, Any]]:
    return [coerce_t5_input_item(item, source=source) for item in items]


def select_t5_items(*, passed_items: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    if limit > 0:
        return passed_items[:limit]
    return passed_items


def build_t5_argv(config: T5GateConfig) -> list[str]:
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


def partition_t5_items(
    items: list[dict[str, Any]],
    reports: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    passed: list[dict[str, Any]] = []
    quarantined: list[dict[str, Any]] = []
    for item, report in zip(items, reports):
        if report.get("status") == "match":
            passed.append(item)
        else:
            quarantined.append(item)
    return passed, quarantined
