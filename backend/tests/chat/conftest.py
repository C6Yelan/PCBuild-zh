from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import backend.services.chat.provider_caller as chat_provider_caller


class FakeChatSettings:
    def __init__(
        self,
        *,
        raw_snapshot_dir: str | Path | None = None,
        max_output_chars: int = 4000,
        p2_max_value_len: int = 120,
        p2_max_specs_per_part: int = 12,
        p2_spec_whitelist_by_category: dict[str, Any] | None = None,
    ) -> None:
        self.ai_oai_base_url = "https://example.invalid/v1"
        self.ai_oai_api_key = None
        self.ai_model = "gpt-4o-mini"
        self.ai_timeout_seconds = 10.0
        self.ai_max_output_chars = max_output_chars
        self.ai_provider = "openai_compat"
        self.p2_max_value_len = p2_max_value_len
        self.p2_max_specs_per_part = p2_max_specs_per_part
        self.p2_spec_whitelist_by_category = p2_spec_whitelist_by_category or {}
        if raw_snapshot_dir is not None:
            self.ai_raw_snapshot_dir = str(raw_snapshot_dir)


@pytest.fixture
def snapshot_temp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def fake_chat_settings():
    def build(
        *,
        raw_snapshot_dir: str | Path | None = None,
        max_output_chars: int = 4000,
        p2_max_value_len: int = 120,
        p2_max_specs_per_part: int = 12,
        p2_spec_whitelist_by_category: dict[str, Any] | None = None,
    ) -> FakeChatSettings:
        return FakeChatSettings(
            raw_snapshot_dir=raw_snapshot_dir,
            max_output_chars=max_output_chars,
            p2_max_value_len=p2_max_value_len,
            p2_max_specs_per_part=p2_max_specs_per_part,
            p2_spec_whitelist_by_category=p2_spec_whitelist_by_category,
        )

    return build


@pytest.fixture
def provider_result_factory():
    def build(
        *,
        request_id: str = "req-1",
        text: str = "ok",
        messages: list[dict[str, str]] | None = None,
        finish_reason: str | None = "stop",
        usage: dict[str, int] | None = None,
        upstream_request_id: str | None = "up-1",
        endpoint: str = "https://example.invalid/v1/chat/completions",
        status_code: int = 200,
        request_headers: dict[str, str] | None = None,
        request_json: dict[str, Any] | None = None,
        response_headers: dict[str, str] | None = None,
        response_json: dict[str, Any] | None = None,
        raw_response_text: str | None = None,
    ) -> chat_provider_caller.ProviderCallResult:
        resolved_messages = messages or [{"role": "user", "content": "hi"}]
        resolved_response_json = response_json or {
            "choices": [{"message": {"content": text}}]
        }
        return chat_provider_caller.ProviderCallResult(
            text=text,
            endpoint=endpoint,
            status_code=status_code,
            request_headers=request_headers
            or {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Client-Request-Id": request_id,
            },
            request_json=request_json
            or {"model": "gpt-4o-mini", "messages": resolved_messages},
            response_headers=response_headers
            or {"x-request-id": upstream_request_id or ""},
            response_json=resolved_response_json,
            raw_response_text=raw_response_text
            or json.dumps(resolved_response_json, ensure_ascii=False),
            upstream_request_id=upstream_request_id,
            finish_reason=finish_reason,
            usage=usage,
        )

    return build
