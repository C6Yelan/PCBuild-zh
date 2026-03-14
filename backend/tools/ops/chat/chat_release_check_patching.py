from __future__ import annotations

import json
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import backend.services.chat.provider_caller as chat_provider_caller
import backend.services.chat.service as chat_service
from backend.services.chat.clients.openai_compat_client import OpenAICompatError
from backend.services.chat.config import get_ai_settings
from backend.services.chat.contracts import ChatRequest


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
