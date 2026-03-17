# backend/tools/ops/chat/chat_release_check_scenarios.py
from __future__ import annotations

import json
from contextlib import ExitStack
from functools import partial
from pathlib import Path
from typing import Any, Callable
from unittest.mock import patch

import httpx

import backend.services.chat.clients.openai_compat_client as oai_client
from backend.services.chat.clients.openai_compat_client import OpenAICompatError

_ReadJsonArtifact = Callable[[Path], dict[str, Any]]
_RunServiceCase = Callable[..., tuple[Any, Path]]
_ReleaseCheckRunner = Callable[[], dict[str, Any]]


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _check_staged_success(
    snapshot_root: Path,
    *,
    read_json_artifact: _ReadJsonArtifact,
    run_service_case: _RunServiceCase,
) -> dict[str, Any]:
    response, snapshot_dir = run_service_case(
        snapshot_root=snapshot_root,
        provider_result_text="這是一段正常且可發布的建議內容，包含處理器與主機板。",
    )
    meta = read_json_artifact(snapshot_dir / "meta.json")
    _assert(response.error_type is None, "expected staged success error_type=None")
    _assert((snapshot_dir / "staging_record.json").is_file(), "missing staging_record.json")
    _assert(meta["staging_status"] == "staged", "staging_status should be staged")
    _assert(
        meta["quarantine_status"] == "not_quarantined",
        "quarantine_status should be not_quarantined",
    )
    return {"request_id": response.request_id, "snapshot_dir": str(snapshot_dir)}


def _check_validation_failed(
    snapshot_root: Path,
    *,
    read_json_artifact: _ReadJsonArtifact,
    run_service_case: _RunServiceCase,
) -> dict[str, Any]:
    response, snapshot_dir = run_service_case(
        snapshot_root=snapshot_root,
        provider_result_text="\0\u200b \t\n",
    )
    meta = read_json_artifact(snapshot_dir / "meta.json")
    _assert(
        response.error_type == "validation_failed",
        "expected validation_failed error_type",
    )
    _assert(f"request_id={response.request_id}" in response.text, "missing request_id in text")
    _assert(
        (snapshot_dir / "quarantine_entry.json").is_file(),
        "missing quarantine_entry.json",
    )
    _assert(meta["staging_status"] == "skipped", "staging_status should be skipped")
    _assert(
        meta["quarantine_status"] == "quarantined",
        "quarantine_status should be quarantined",
    )
    return {"request_id": response.request_id, "snapshot_dir": str(snapshot_dir)}


def _check_dq_failed(
    snapshot_root: Path,
    *,
    read_json_artifact: _ReadJsonArtifact,
    run_service_case: _RunServiceCase,
) -> dict[str, Any]:
    response, snapshot_dir = run_service_case(
        snapshot_root=snapshot_root,
        provider_result_text="短",
    )
    meta = read_json_artifact(snapshot_dir / "meta.json")
    _assert(response.error_type == "dq_failed", "expected dq_failed error_type")
    _assert(f"request_id={response.request_id}" in response.text, "missing request_id in text")
    _assert(
        (snapshot_dir / "quarantine_entry.json").is_file(),
        "missing quarantine_entry.json",
    )
    _assert(meta["dq_status"] == "fail", "dq_status should be fail")
    index_path = snapshot_root / "_quarantine" / "quarantine_index.jsonl"
    _assert(index_path.is_file(), "missing quarantine_index.jsonl")
    index_entries = [json.loads(line) for line in index_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    _assert(
        any(entry.get("request_id") == response.request_id for entry in index_entries),
        "request_id not found in quarantine index",
    )
    return {"request_id": response.request_id, "snapshot_dir": str(snapshot_dir)}


def _check_provider_error(
    snapshot_root: Path,
    *,
    read_json_artifact: _ReadJsonArtifact,
    run_service_case: _RunServiceCase,
) -> dict[str, Any]:
    response, snapshot_dir = run_service_case(
        snapshot_root=snapshot_root,
        provider_error=OpenAICompatError("network_error", endpoint="https://example.invalid/v1"),
    )
    meta = read_json_artifact(snapshot_dir / "meta.json")
    _assert(response.error_type == "network_error", "expected network_error")
    _assert(f"request_id={response.request_id}" in response.text, "missing request_id in text")
    _assert(
        not (snapshot_dir / "staging_record.json").exists(),
        "staging_record.json should not exist",
    )
    _assert(
        not (snapshot_dir / "quarantine_entry.json").exists(),
        "quarantine_entry.json should not exist",
    )
    _assert(meta["staging_status"] == "skipped", "staging_status should be skipped")
    _assert(
        meta["quarantine_status"] == "not_applicable",
        "quarantine_status should be not_applicable",
    )
    return {"request_id": response.request_id, "snapshot_dir": str(snapshot_dir)}


def _check_retry_backoff() -> dict[str, Any]:
    calls = {"count": 0}
    retry_events: list[tuple[str, dict[str, Any]]] = []

    class _Response:
        status_code = 200
        headers = httpx.Headers({"x-request-id": "up-retry"})
        text = '{"choices":[{"message":{"content":"ok"}}]}'

        def json(self) -> dict[str, object]:
            return {
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }

    def _fake_post(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise httpx.TimeoutException("timeout")
        return _Response()

    with ExitStack() as stack:
        stack.enter_context(patch.object(oai_client.httpx, "post", _fake_post))
        stack.enter_context(patch.object(oai_client, "sleep", lambda *args, **kwargs: None))
        stack.enter_context(
            patch.object(
                oai_client,
                "log_operation",
                lambda event, **fields: retry_events.append((event, fields)),
            )
        )
        result = oai_client.generate_openai_compat_completion(
            base_url="https://example.invalid/v1",
            api_key=None,
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "hi"}],
            timeout_seconds=1.0,
            client_request_id="req-release-retry",
            provider="openai_compat",
        )

    _assert(result.text == "ok", "retry path did not succeed")
    _assert(calls["count"] == 2, "retry count should equal MAX_CHAT_ATTEMPTS")
    ai_retry_events = [fields for event, fields in retry_events if event == "ai_retry"]
    _assert(ai_retry_events, "ai_retry event missing")
    return {
        "attempts": calls["count"],
        "retry_events": len(ai_retry_events),
        "request_id": "req-release-retry",
    }


def _build_p10_checks(
    snapshot_root: Path,
    *,
    read_json_artifact: _ReadJsonArtifact,
    run_service_case: _RunServiceCase,
) -> list[tuple[str, _ReleaseCheckRunner]]:
    scenario_runner = partial(
        _check_staged_success,
        snapshot_root,
        read_json_artifact=read_json_artifact,
        run_service_case=run_service_case,
    )
    validation_runner = partial(
        _check_validation_failed,
        snapshot_root,
        read_json_artifact=read_json_artifact,
        run_service_case=run_service_case,
    )
    dq_runner = partial(
        _check_dq_failed,
        snapshot_root,
        read_json_artifact=read_json_artifact,
        run_service_case=run_service_case,
    )
    provider_runner = partial(
        _check_provider_error,
        snapshot_root,
        read_json_artifact=read_json_artifact,
        run_service_case=run_service_case,
    )
    return [
        ("staged_success", scenario_runner),
        ("validation_failed", validation_runner),
        ("dq_failed", dq_runner),
        ("provider_error", provider_runner),
        ("retry_backoff", _check_retry_backoff),
    ]
