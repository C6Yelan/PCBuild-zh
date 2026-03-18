# backend/services/chat/service/decisions.py
"""Gate, DQ, and publish-decision helpers for chat orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from backend.services.chat.dq import DQReport
from backend.services.chat.gate import TextValidationReport
from .response import (
    PublishedChatResult,
    publish_chat_response,
    truncate_output_text,
)


@dataclass(slots=True)
class DecisionOutcome:
    response_text: str
    validation: TextValidationReport
    dq_report: DQReport | None
    published: PublishedChatResult
    gate_status: str
    dq_status: str
    staging_status: str
    quarantine_status: str


def _append_unique_warnings(warnings: list[str], values: list[str]) -> None:
    for value in values:
        if value not in warnings:
            warnings.append(value)


def evaluate_decision_outcome(
    *,
    request_id: str,
    text: str,
    max_output_chars: int,
    warnings: list[str],
    categories: list[str],
    compressed_candidates: dict[str, list[dict[str, object]]],
    context_pack_text: str | None,
    triggered_retrieval: bool,
    validate_text_response: Callable[..., TextValidationReport],
    evaluate_text_dq: Callable[..., DQReport],
) -> DecisionOutcome:
    response_text = truncate_output_text(
        text,
        max_chars=max_output_chars,
        warnings=warnings,
    )
    validation = validate_text_response(
        response_text,
        max_chars=max_output_chars,
    )
    _append_unique_warnings(warnings, validation.warnings)
    response_text = validation.sanitized_text

    dq_report: DQReport | None = None
    response_error_type: str | None = None
    if not validation.passed:
        response_error_type = "validation_failed"
    else:
        dq_report = evaluate_text_dq(
            text=response_text,
            request_categories=categories,
            compressed_candidates=compressed_candidates,
            context_pack_text=context_pack_text,
            triggered_retrieval=triggered_retrieval,
        )
        _append_unique_warnings(warnings, dq_report.warnings)
        if not dq_report.passed:
            response_error_type = "dq_failed"

    published = publish_chat_response(
        request_id=request_id,
        staged_public_text=response_text,
        error_type=response_error_type,
    )
    gate_status = "pass" if validation.passed else "fail"
    dq_status = (
        "skipped"
        if dq_report is None
        else "pass"
        if dq_report.passed
        else "fail"
    )
    staging_status = "staged" if gate_status == "pass" and dq_status == "pass" else "skipped"
    quarantine_status = "not_quarantined" if staging_status == "staged" else "quarantined"
    return DecisionOutcome(
        response_text=response_text,
        validation=validation,
        dq_report=dq_report,
        published=published,
        gate_status=gate_status,
        dq_status=dq_status,
        staging_status=staging_status,
        quarantine_status=quarantine_status,
    )


__all__ = [
    "DecisionOutcome",
    "evaluate_decision_outcome",
]
