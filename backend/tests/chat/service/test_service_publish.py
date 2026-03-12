# backend/tests/chat/service/test_service_publish.py
from __future__ import annotations

import json
from pathlib import Path

import backend.services.chat.provider_caller as chat_provider_caller
import backend.services.chat.service as chat_service
from backend.services.chat.clients.openai_compat_client import (
    OpenAICompatError,
)
from backend.services.chat.contracts import ChatRequest


def test_publish_staged_response_keeps_public_text_and_logs_statuses(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir, max_output_chars=200)
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: provider_result_factory(
            text="這是一段正常的建議內容，包含 CPU 與主機板。",
            request_id=kwargs["request_id"],
            usage={"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
        ),
    )
    monkeypatch.setattr(
        chat_service,
        "log_operation",
        lambda event, **fields: events.append((event, fields)),
    )

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.error_type is None
    assert response.text == "這是一段正常的建議內容，包含 CPU 與主機板。"
    assert f"request_id={response.request_id}" not in response.text

    ai_fields = [fields for event, fields in events if event == "ai_call"]
    assert len(ai_fields) == 1
    assert ai_fields[0]["gate_status"] == "pass"
    assert ai_fields[0]["dq_status"] == "pass"
    assert ai_fields[0]["staging_status"] == "staged"
    assert ai_fields[0]["quarantine_status"] == "not_quarantined"


def test_publish_validation_failed_includes_request_id_and_quarantine_reason(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir, max_output_chars=200)

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: provider_result_factory(
            text="\0\u200b \t\n",
            request_id=kwargs["request_id"],
            usage={"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
        ),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.error_type == "validation_failed"
    assert f"request_id={response.request_id}" in response.text

    quarantine_entry = json.loads(
        (snapshot_temp_dir / response.request_id / "quarantine_entry.json").read_text(
            encoding="utf-8"
        )
    )
    assert quarantine_entry["publish_blocked"] is True
    assert quarantine_entry["publish_reason"] == "validation_failed"


def test_publish_dq_failed_includes_request_id_and_quarantine_reason(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir, max_output_chars=200)

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: provider_result_factory(
            text="短",
            request_id=kwargs["request_id"],
            usage={"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
        ),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.error_type == "dq_failed"
    assert f"request_id={response.request_id}" in response.text

    quarantine_entry = json.loads(
        (snapshot_temp_dir / response.request_id / "quarantine_entry.json").read_text(
            encoding="utf-8"
        )
    )
    assert quarantine_entry["publish_blocked"] is True
    assert quarantine_entry["publish_reason"] == "dq_failed"


def test_publish_provider_error_keeps_request_id_and_skips_stage_and_quarantine(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir, max_output_chars=200)
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: (_ for _ in ()).throw(
            OpenAICompatError("network_error", endpoint="https://example.invalid/v1")
        ),
    )
    monkeypatch.setattr(
        chat_service,
        "log_operation",
        lambda event, **fields: events.append((event, fields)),
    )

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.error_type == "network_error"
    assert f"request_id={response.request_id}" in response.text
    snapshot_dir = snapshot_temp_dir / response.request_id
    assert not (snapshot_dir / "staging_record.json").exists()
    assert not (snapshot_dir / "quarantine_entry.json").exists()

    ai_fields = [fields for event, fields in events if event == "ai_call"]
    assert len(ai_fields) == 1
    assert ai_fields[0]["staging_status"] == "skipped"
    assert ai_fields[0]["quarantine_status"] == "not_applicable"
