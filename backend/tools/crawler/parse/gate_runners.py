"""Schema and DQ gate runner facade helpers for crawl-parse."""

from __future__ import annotations

from typing import Any

from backend.services.crawler.dq_gate import run_dq_gate
from backend.services.crawler.schema_gate.validate import validate_payload_fail_fast


def validate_schema_payload(*, source: str, payload: list[dict[str, Any]]) -> None:
    validate_payload_fail_fast(source_id=source, payload=payload)


def run_dq_pipeline(payload: list[dict[str, Any]]) -> Any:
    return run_dq_gate(payload)


__all__ = ["run_dq_pipeline", "validate_schema_payload"]
