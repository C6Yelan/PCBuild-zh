"""Snapshot persistence seam for chat artifacts.

Round-1 scope:
- build request-context / lineage / validation / dq payloads
- write snapshot artifacts and meta.json without changing file names or shape
- expose minimal snapshot-root / JSON-loading helpers for inspect CLIs
- serve as the stable snapshot patch point for service-level tests
"""
# backend/services/chat/snapshot_store.py
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from backend.core.oplog import log_operation
from backend.services.chat.clients.openai_compat_client import OpenAICompatError
from backend.services.chat.config import AISettings
from backend.services.chat.dq import DQReport
from backend.services.chat.gate import TextValidationReport
from backend.services.chat.provider_caller import (
    ProviderCallResult,
    ProviderDispatchError,
)

_SNAPSHOT_DIR_FALLBACK = "/tmp/pcbuild_ai_raw_snapshots"
_REDACTED = "[REDACTED]"
_SENSITIVE_FIELD_NAMES = {
    "authorization",
    "api_key",
    "x_api_key",
    "x-api-key",
    "openai_api_key",
    "gemini_api_key",
    "google_api_key",
    "ai_oai_api_key",
    "ai_api_key",
}
_BEARER_TOKEN_RE = re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]+")


def snapshot_root(settings: AISettings) -> Path:
    raw_dir = getattr(settings, "ai_raw_snapshot_dir", _SNAPSHOT_DIR_FALLBACK)
    normalized = str(raw_dir or _SNAPSHOT_DIR_FALLBACK).strip() or _SNAPSHOT_DIR_FALLBACK
    return Path(normalized)


def snapshot_dir(settings: AISettings, request_id: str) -> Path:
    return snapshot_root(settings) / request_id


def write_json_file(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def write_text_file(path: Path, payload: str) -> None:
    path.write_text(payload, encoding="utf-8")


def read_json_file(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _is_sensitive_key(key: str | None) -> bool:
    if not key:
        return False
    lowered = key.strip().lower()
    return lowered in _SENSITIVE_FIELD_NAMES or "api_key" in lowered


def _redact_string(value: str, *, key: str | None = None) -> str:
    if _is_sensitive_key(key):
        return _REDACTED
    return _BEARER_TOKEN_RE.sub("Bearer [REDACTED]", value)


def redact_snapshot_value(value: Any, *, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {
            str(item_key): redact_snapshot_value(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [redact_snapshot_value(item) for item in value]
    if isinstance(value, tuple):
        return [redact_snapshot_value(item) for item in value]
    if isinstance(value, str):
        return _redact_string(value, key=key)
    if _is_sensitive_key(key):
        return _REDACTED
    return value


def build_request_context_payload(
    *,
    request_id: str,
    provider: str,
    model: str,
    snapshot_id: str,
    context_pack_hash: str,
    request_mode: str,
    demand_source: str,
    triggered_retrieval: bool,
    categories: list[str],
    top_k: int,
    env: str,
    warnings: list[str],
    has_context_pack: bool,
    message_chars: int,
    history_turns: int,
) -> dict[str, Any]:
    return {
        "request_id": request_id,
        "provider": provider,
        "model": model,
        "snapshot_id": snapshot_id,
        "context_pack_hash": context_pack_hash,
        "request_mode": request_mode,
        "demand_source": demand_source,
        "triggered_retrieval": triggered_retrieval,
        "categories": categories,
        "top_k": top_k,
        "env": env,
        "warnings": list(warnings),
        "has_context_pack": has_context_pack,
        "message_chars": message_chars,
        "history_turns": history_turns,
    }


def build_candidate_lineage_categories(
    compressed_candidates: dict[str, list[dict[str, object]]],
) -> dict[str, list[dict[str, Any]]]:
    def _optional_str(value: object) -> str | None:
        if value is None:
            return None
        return str(value)

    categories: dict[str, list[dict[str, Any]]] = {}
    for category, items in compressed_candidates.items():
        category_items: list[dict[str, Any]] = []
        for item in items:
            category_items.append(
                {
                    "part_id": _optional_str(item.get("part_id")),
                    "category": _optional_str(item.get("category")) or category,
                    "display_name": _optional_str(item.get("display_name")),
                    "source": _optional_str(item.get("source")),
                    "source_url": _optional_str(item.get("source_url")),
                    "snapshot_id": _optional_str(item.get("snapshot_id")),
                    "run_id": _optional_str(item.get("run_id")),
                }
            )
        categories[category] = category_items
    return categories


def _build_lineage_payload(
    *,
    request_id: str,
    context_pack_hash: str,
    compressed_candidates: dict[str, list[dict[str, object]]],
) -> dict[str, Any]:
    return {
        "request_id": request_id,
        "context_pack_hash": context_pack_hash,
        "categories": build_candidate_lineage_categories(compressed_candidates),
    }


def _build_validation_payload(
    validation_report: TextValidationReport | None,
) -> dict[str, Any] | None:
    if validation_report is None:
        return None
    return {
        "passed": validation_report.passed,
        "reasons": list(validation_report.reasons),
        "warnings": list(validation_report.warnings),
        "removed_chars_count": validation_report.removed_chars_count,
        "max_chars": validation_report.max_chars,
        "original_length": validation_report.original_length,
        "sanitized_length": validation_report.sanitized_length,
    }


def _build_dq_payload(dq_report: DQReport | None) -> dict[str, Any] | None:
    if dq_report is None:
        return None
    return {
        "passed": dq_report.passed,
        "reasons": list(dq_report.reasons),
        "warnings": list(dq_report.warnings),
        "metrics": dict(dq_report.metrics),
        "quarantine": dq_report.quarantine,
    }


def _persist_snapshot_artifacts(
    *,
    snapshot_dir: Path,
    raw_request: dict[str, Any],
    raw_response: dict[str, Any],
    request_context: dict[str, Any],
    validation_report: dict[str, Any] | None,
    dq_report: dict[str, Any] | None,
    context_pack_text: str | None,
    compressed_candidates: dict[str, list[dict[str, object]]],
    drop_log: dict[str, dict[str, object]],
    lineage: dict[str, Any] | None,
) -> list[str]:
    artifacts: list[str] = []

    write_json_file(snapshot_dir / "raw_request.json", raw_request)
    artifacts.append("raw_request.json")

    write_json_file(snapshot_dir / "raw_response.json", raw_response)
    artifacts.append("raw_response.json")

    write_json_file(snapshot_dir / "request_context.json", request_context)
    artifacts.append("request_context.json")

    if validation_report is not None:
        write_json_file(snapshot_dir / "validation_report.json", validation_report)
        artifacts.append("validation_report.json")

    if dq_report is not None:
        write_json_file(snapshot_dir / "dq_report.json", dq_report)
        artifacts.append("dq_report.json")

    if context_pack_text:
        write_text_file(snapshot_dir / "context_pack.txt", context_pack_text)
        artifacts.append("context_pack.txt")

    if compressed_candidates:
        write_json_file(
            snapshot_dir / "compressed_candidates.json",
            redact_snapshot_value(compressed_candidates),
        )
        artifacts.append("compressed_candidates.json")

        write_json_file(
            snapshot_dir / "drop_log.json",
            redact_snapshot_value(drop_log),
        )
        artifacts.append("drop_log.json")

        if lineage is not None:
            write_json_file(
                snapshot_dir / "lineage.json",
                redact_snapshot_value(lineage),
            )
            artifacts.append("lineage.json")

    return artifacts


def _write_ai_snapshot(
    *,
    settings: AISettings,
    request_id: str,
    provider: str,
    model: str,
    context_pack_hash: str,
    client_request_id: str,
    latency_ms: int,
    ok: bool,
    error_type: str | None,
    messages: list[dict[str, str]],
    request_mode: str,
    demand_source: str,
    triggered_retrieval: bool,
    categories: list[str],
    top_k: int,
    env: str,
    warnings: list[str],
    message_chars: int,
    history_turns: int,
    context_pack_text: str | None,
    compressed_candidates: dict[str, list[dict[str, object]]],
    drop_log: dict[str, dict[str, object]],
    validation_report: TextValidationReport | None = None,
    dq_report: DQReport | None = None,
    provider_result: ProviderCallResult | None = None,
    provider_error: OpenAICompatError | ProviderDispatchError | None = None,
) -> str:
    snapshot_id = f"file:{request_id}"
    request_snapshot_dir = snapshot_dir(settings, request_id)
    request_snapshot_dir.mkdir(parents=True, exist_ok=True)

    endpoint = provider_result.endpoint if provider_result else provider_error.endpoint if provider_error else "-"
    request_headers = (
        provider_result.request_headers
        if provider_result
        else {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Client-Request-Id": client_request_id,
        }
    )
    request_json = (
        provider_result.request_json
        if provider_result
        else provider_error.request_json if provider_error else {"model": model, "messages": messages}
    )
    raw_request = {
        "provider": provider,
        "model": model,
        "messages": messages,
        "context_pack_hash": context_pack_hash,
        "endpoint": endpoint or "-",
        "client_request_id": client_request_id,
        "request_headers": redact_snapshot_value(request_headers),
        "request_json": redact_snapshot_value(request_json),
    }

    response_headers = (
        provider_result.response_headers
        if provider_result
        else provider_error.response_headers if provider_error else {}
    )
    response_json = (
        provider_result.response_json
        if provider_result
        else provider_error.response_json if provider_error else None
    )
    raw_response_text = (
        provider_result.raw_response_text
        if provider_result
        else provider_error.raw_response_text if provider_error else ""
    )
    upstream_request_id = (
        provider_result.upstream_request_id
        if provider_result
        else provider_error.upstream_request_id if provider_error else None
    )
    status_code = (
        provider_result.status_code
        if provider_result
        else provider_error.status_code if provider_error else None
    )
    raw_response = {
        "status_code": status_code,
        "response_headers": redact_snapshot_value(response_headers),
        "response_json": redact_snapshot_value(response_json),
        "raw_response_text": redact_snapshot_value(raw_response_text),
        "upstream_request_id": upstream_request_id,
    }

    request_context = build_request_context_payload(
        request_id=request_id,
        provider=provider,
        model=model,
        snapshot_id=snapshot_id,
        context_pack_hash=context_pack_hash,
        request_mode=request_mode,
        demand_source=demand_source,
        triggered_retrieval=triggered_retrieval,
        categories=list(categories),
        top_k=top_k,
        env=env,
        warnings=warnings,
        has_context_pack=bool(context_pack_text),
        message_chars=message_chars,
        history_turns=history_turns,
    )
    lineage = (
        _build_lineage_payload(
            request_id=request_id,
            context_pack_hash=context_pack_hash,
            compressed_candidates=compressed_candidates,
        )
        if compressed_candidates
        else None
    )

    artifacts = _persist_snapshot_artifacts(
        snapshot_dir=request_snapshot_dir,
        raw_request=raw_request,
        raw_response=raw_response,
        request_context=request_context,
        validation_report=_build_validation_payload(validation_report),
        dq_report=_build_dq_payload(dq_report),
        context_pack_text=context_pack_text,
        compressed_candidates=compressed_candidates,
        drop_log=drop_log,
        lineage=lineage,
    )

    meta = {
        "request_id": request_id,
        "provider": provider,
        "model": model,
        "context_pack_hash": context_pack_hash,
        "latency_ms": latency_ms,
        "ok": ok,
        "error_type": error_type or "-",
        "snapshot_id": snapshot_id,
        "upstream_request_id": upstream_request_id,
        "status_code": status_code,
        "request_mode": request_mode,
        "demand_source": demand_source,
        "triggered_retrieval": triggered_retrieval,
        "gate_status": (
            "pass"
            if validation_report is None or validation_report.passed
            else "fail"
        ),
        "gate_reasons": list(validation_report.reasons) if validation_report else [],
        "dq_status": (
            "skipped"
            if dq_report is None
            else "pass"
            if dq_report.passed
            else "fail"
        ),
        "dq_reasons": list(dq_report.reasons) if dq_report else [],
        "staging_status": "skipped",
        "quarantine_status": (
            "not_applicable" if provider_error is not None else "not_quarantined"
        ),
        "artifacts": [*artifacts, "meta.json"],
    }

    write_json_file(request_snapshot_dir / "meta.json", meta)
    return snapshot_id


def persist_ai_snapshot(
    *,
    settings: AISettings,
    warnings: list[str],
    request_id: str,
    provider: str,
    model: str,
    context_pack_hash: str,
    latency_ms: int,
    ok: bool,
    error_type: str | None,
    messages: list[dict[str, str]],
    request_mode: str,
    demand_source: str,
    triggered_retrieval: bool,
    categories: list[str],
    top_k: int,
    env: str,
    message_chars: int,
    history_turns: int,
    context_pack_text: str | None,
    compressed_candidates: dict[str, list[dict[str, object]]],
    drop_log: dict[str, dict[str, object]],
    validation_report: TextValidationReport | None = None,
    dq_report: DQReport | None = None,
    provider_result: ProviderCallResult | None = None,
    provider_error: OpenAICompatError | ProviderDispatchError | None = None,
) -> str:
    try:
        return _write_ai_snapshot(
            settings=settings,
            request_id=request_id,
            provider=provider,
            model=model,
            context_pack_hash=context_pack_hash,
            client_request_id=request_id,
            latency_ms=latency_ms,
            ok=ok,
            error_type=error_type,
            messages=messages,
            request_mode=request_mode,
            demand_source=demand_source,
            triggered_retrieval=triggered_retrieval,
            categories=categories,
            top_k=top_k,
            env=env,
            warnings=warnings,
            message_chars=message_chars,
            history_turns=history_turns,
            context_pack_text=context_pack_text,
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
            validation_report=validation_report,
            dq_report=dq_report,
            provider_result=provider_result,
            provider_error=provider_error,
        )
    except Exception as exc:
        if "ai_snapshot_write_failed" not in warnings:
            warnings.append("ai_snapshot_write_failed")
        log_operation(
            "snapshot_write_failed",
            request_id=request_id,
            provider=provider,
            model=model,
            context_pack_hash=context_pack_hash,
            error_type=type(exc).__name__,
        )
        return "-"


def update_snapshot_meta(
    *,
    settings: AISettings,
    request_id: str,
    staging_status: str,
    quarantine_status: str,
    artifact_name: str | None = None,
) -> None:
    meta_path = snapshot_dir(settings, request_id) / "meta.json"
    if not meta_path.is_file():
        return

    meta = read_json_file(meta_path)
    meta["staging_status"] = staging_status
    meta["quarantine_status"] = quarantine_status

    artifacts = list(meta.get("artifacts", []))
    if artifact_name and artifact_name not in artifacts:
        if "meta.json" in artifacts:
            artifacts.insert(artifacts.index("meta.json"), artifact_name)
        else:
            artifacts.append(artifact_name)
    meta["artifacts"] = artifacts
    write_json_file(meta_path, meta)


__all__ = [
    "build_candidate_lineage_categories",
    "persist_ai_snapshot",
    "read_json_file",
    "snapshot_dir",
    "snapshot_root",
    "update_snapshot_meta",
]
