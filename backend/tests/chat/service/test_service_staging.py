# backend/tests/chat/service/test_service_staging.py
from __future__ import annotations

import json
from pathlib import Path

import backend.services.chat.provider_caller as chat_provider_caller
import backend.services.chat.service as chat_service
from backend.services.chat.contracts import ChatRequest


def test_generate_chat_reply_stages_successful_response(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir)
    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: provider_result_factory(
            text="這是一段正常且可用的電腦建議內容。",
            request_id=kwargs["request_id"],
        ),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    snapshot_dir = snapshot_temp_dir / response.request_id
    assert (snapshot_dir / "staging_record.json").exists()
    assert not (snapshot_dir / "quarantine_entry.json").exists()
    assert (snapshot_temp_dir / "_staging" / f"{response.request_id}.staging.json").exists()

    meta = json.loads((snapshot_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["staging_status"] == "staged"
    assert meta["quarantine_status"] == "not_quarantined"
    staging_record = json.loads((snapshot_dir / "staging_record.json").read_text(encoding="utf-8"))
    assert staging_record["published"] is True
    assert staging_record["publish_blocked"] is False
    assert staging_record["publish_reason"] == "staged_pass"
    assert staging_record["data_versions"] == {}


def test_generate_chat_reply_quarantines_dq_fail(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir)
    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: provider_result_factory(text="短", request_id=kwargs["request_id"]),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.error_type == "dq_failed"
    assert response.text.startswith("目前資料不足，請補充需求後再試。request_id=")

    snapshot_dir = snapshot_temp_dir / response.request_id
    assert (snapshot_dir / "quarantine_entry.json").exists()
    assert not (snapshot_dir / "staging_record.json").exists()
    assert (snapshot_temp_dir / "_quarantine" / f"{response.request_id}.quarantine.json").exists()

    meta = json.loads((snapshot_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["staging_status"] == "skipped"
    assert meta["quarantine_status"] == "quarantined"
    quarantine_entry = json.loads(
        (snapshot_dir / "quarantine_entry.json").read_text(encoding="utf-8")
    )
    assert quarantine_entry["published"] is False
    assert quarantine_entry["publish_blocked"] is True
    assert quarantine_entry["publish_reason"] == "dq_failed"

    index_path = snapshot_temp_dir / "_quarantine" / "quarantine_index.jsonl"
    index_entries = [json.loads(line) for line in index_path.read_text(encoding="utf-8").splitlines()]
    assert index_entries[-1]["request_id"] == response.request_id
    assert index_entries[-1]["dq_status"] == "fail"


def test_generate_chat_reply_quarantines_validation_fail(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir)
    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: provider_result_factory(
            text="\0\u200b \t\n",
            request_id=kwargs["request_id"],
        ),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.error_type == "validation_failed"
    assert response.text.startswith("目前 AI 回覆格式異常，請稍後再試。request_id=")

    snapshot_dir = snapshot_temp_dir / response.request_id
    assert (snapshot_dir / "quarantine_entry.json").exists()
    assert not (snapshot_dir / "staging_record.json").exists()

    meta = json.loads((snapshot_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["staging_status"] == "skipped"
    assert meta["quarantine_status"] == "quarantined"
    assert meta["dq_status"] == "skipped"
    quarantine_entry = json.loads(
        (snapshot_dir / "quarantine_entry.json").read_text(encoding="utf-8")
    )
    assert quarantine_entry["publish_reason"] == "validation_failed"


def test_provider_error_path_skips_staging_and_quarantine(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir)
    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: (_ for _ in ()).throw(
            chat_provider_caller.ProviderDispatchError(
                "provider_not_ready",
                "not ready",
                request_json={"model": settings.ai_model, "messages": kwargs["messages"]},
            )
        ),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    snapshot_dir = snapshot_temp_dir / response.request_id
    assert not (snapshot_dir / "staging_record.json").exists()
    assert not (snapshot_dir / "quarantine_entry.json").exists()

    meta = json.loads((snapshot_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["staging_status"] == "skipped"
    assert meta["quarantine_status"] == "not_applicable"
