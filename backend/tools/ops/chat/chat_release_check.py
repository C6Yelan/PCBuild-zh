"""Deterministic chat acceptance harness.

Keep the CLI module path stable for existing SOP/CI usage, but treat this file
as test-harness surface rather than official runtime ops.
"""

# backend/tools/ops/chat_release_check.py
from __future__ import annotations

import argparse
import json
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence
from unittest.mock import patch

import httpx

import backend.services.chat.clients.openai_compat_client as oai_client
import backend.services.chat.provider_caller as chat_provider_caller
import backend.services.chat.service as chat_service
from backend.services.chat.clients.openai_compat_client import OpenAICompatError
from backend.services.chat.config import get_ai_settings
from backend.services.chat.contracts import ChatRequest
from backend.tools.ops.chat.chat_artifact_helpers import emit_json_payload, read_json_artifact


def _isolated_snapshot_root() -> Path:
    settings = get_ai_settings()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    root = Path(settings.ai_raw_snapshot_dir) / "_release_checks" / run_id
    root.mkdir(parents=True, exist_ok=True)
    return root


def _isolated_settings(snapshot_root: Path) -> Any:
    settings = get_ai_settings()
    return settings.model_copy(update={"ai_raw_snapshot_dir": str(snapshot_root)})


def _provider_result(*, request_id: str, text: str) -> chat_provider_caller.ProviderCallResult:
    payload = {"choices": [{"message": {"content": text}}]}
    return chat_provider_caller.ProviderCallResult(
        text=text,
        endpoint="https://example.invalid/v1/chat/completions",
        status_code=200,
        request_headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Client-Request-Id": request_id,
        },
        request_json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hi"}],
        },
        response_headers={"x-request-id": "up-release-check"},
        response_json=payload,
        raw_response_text=json.dumps(payload, ensure_ascii=False),
        upstream_request_id="up-release-check",
        response_id="resp-release-check",
        finish_reason="stop",
        usage={"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
    )


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _run_service_case(
    *,
    snapshot_root: Path,
    provider_result_text: str | None = None,
    provider_error: OpenAICompatError | None = None,
) -> tuple[Any, Path]:
    settings = _isolated_settings(snapshot_root)

    def _fake_provider_result(**kwargs):
        if provider_error is not None:
            raise provider_error
        return _provider_result(
            request_id=kwargs["request_id"],
            text=provider_result_text or "",
        )

    with ExitStack() as stack:
        stack.enter_context(patch.object(chat_service, "get_ai_settings", lambda: settings))
        stack.enter_context(patch.object(chat_service, "infer_chat_demand", lambda *args, **kwargs: None))
        stack.enter_context(
            patch.object(chat_provider_caller, "generate_provider_result", _fake_provider_result)
        )
        stack.enter_context(patch.object(chat_service, "log_operation", lambda *args, **kwargs: None))
        response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    return response, snapshot_root / response.request_id


def _check_staged_success(snapshot_root: Path) -> dict[str, Any]:
    response, snapshot_dir = _run_service_case(
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


def _check_validation_failed(snapshot_root: Path) -> dict[str, Any]:
    response, snapshot_dir = _run_service_case(
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


def _check_dq_failed(snapshot_root: Path) -> dict[str, Any]:
    response, snapshot_dir = _run_service_case(
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


def _check_provider_error(snapshot_root: Path) -> dict[str, Any]:
    response, snapshot_dir = _run_service_case(
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


def run_p10_release_check() -> dict[str, Any]:
    snapshot_root = _isolated_snapshot_root()
    checks = [
        ("staged_success", lambda: _check_staged_success(snapshot_root)),
        ("validation_failed", lambda: _check_validation_failed(snapshot_root)),
        ("dq_failed", lambda: _check_dq_failed(snapshot_root)),
        ("provider_error", lambda: _check_provider_error(snapshot_root)),
        ("retry_backoff", _check_retry_backoff),
    ]

    summary: dict[str, Any] = {
        "mode": "p10",
        "snapshot_root": str(snapshot_root),
        "passed_checks": [],
        "failed_checks": [],
        "details": {},
    }

    for check_name, runner in checks:
        try:
            summary[check_name] = "pass"
            summary["details"][check_name] = runner()
            summary["passed_checks"].append(check_name)
        except Exception as exc:
            summary[check_name] = "fail"
            summary["failed_checks"].append(check_name)
            summary["details"][check_name] = {
                "error_type": type(exc).__name__,
                "message": str(exc),
            }

    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run deterministic release checks for chat ops.")
    parser.add_argument("--mode", default="p10", choices=["p10"])
    parser.parse_args(argv)

    try:
        summary = run_p10_release_check()
    except Exception as exc:
        summary = {
            "mode": "p10",
            "snapshot_root": "-",
            "staged_success": "fail",
            "validation_failed": "fail",
            "dq_failed": "fail",
            "provider_error": "fail",
            "retry_backoff": "fail",
            "passed_checks": [],
            "failed_checks": [
                "staged_success",
                "validation_failed",
                "dq_failed",
                "provider_error",
                "retry_backoff",
            ],
            "details": {
                "setup": {
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                }
            },
        }
    emit_json_payload(summary)
    if not summary["failed_checks"]:
        print("P10_CHECK_OK")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
