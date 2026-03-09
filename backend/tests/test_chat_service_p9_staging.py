# backend/tests/test_chat_service_p9_staging.py
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import backend.services.chat.service as chat_service
import backend.tools.ops.chat_staging_inspect as chat_staging_inspect
from backend.services.chat.contracts import ChatRequest


class _FakeSettings:
    def __init__(self, raw_snapshot_dir: str) -> None:
        self.ai_oai_base_url = "https://example.invalid/v1"
        self.ai_oai_api_key = None
        self.ai_model = "gpt-4o-mini"
        self.ai_timeout_seconds = 10.0
        self.ai_max_output_chars = 4000
        self.ai_provider = "openai_compat"
        self.ai_raw_snapshot_dir = raw_snapshot_dir
        self.p2_max_value_len = 120
        self.p2_max_specs_per_part = 12
        self.p2_spec_whitelist_by_category = {}


def _provider_result(*, text: str, request_id: str) -> chat_service._ProviderCallResult:
    return chat_service._ProviderCallResult(
        text=text,
        endpoint="https://example.invalid/v1/chat/completions",
        status_code=200,
        request_headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Client-Request-Id": request_id,
        },
        request_json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        response_headers={"x-request-id": "up-1"},
        response_json={"choices": [{"message": {"content": text}}]},
        raw_response_text=json.dumps({"choices": [{"message": {"content": text}}]}, ensure_ascii=False),
        upstream_request_id="up-1",
    )


def test_generate_chat_reply_stages_successful_response(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = _FakeSettings(str(tmp_path))
    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_service,
        "_generate_provider_result",
        lambda **kwargs: _provider_result(
            text="這是一段正常且可用的電腦建議內容。",
            request_id=kwargs["request_id"],
        ),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    snapshot_dir = tmp_path / response.request_id
    assert (snapshot_dir / "staging_record.json").exists()
    assert not (snapshot_dir / "quarantine_entry.json").exists()
    assert (tmp_path / "_staging" / f"{response.request_id}.staging.json").exists()

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
    tmp_path: Path,
) -> None:
    settings = _FakeSettings(str(tmp_path))
    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_service,
        "_generate_provider_result",
        lambda **kwargs: _provider_result(text="短", request_id=kwargs["request_id"]),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.error_type == "dq_failed"
    assert response.text.startswith("目前資料不足，請補充需求後再試。request_id=")

    snapshot_dir = tmp_path / response.request_id
    assert (snapshot_dir / "quarantine_entry.json").exists()
    assert not (snapshot_dir / "staging_record.json").exists()
    assert (tmp_path / "_quarantine" / f"{response.request_id}.quarantine.json").exists()

    meta = json.loads((snapshot_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["staging_status"] == "skipped"
    assert meta["quarantine_status"] == "quarantined"
    quarantine_entry = json.loads(
        (snapshot_dir / "quarantine_entry.json").read_text(encoding="utf-8")
    )
    assert quarantine_entry["published"] is False
    assert quarantine_entry["publish_blocked"] is True
    assert quarantine_entry["publish_reason"] == "dq_failed"

    index_path = tmp_path / "_quarantine" / "quarantine_index.jsonl"
    index_entries = [json.loads(line) for line in index_path.read_text(encoding="utf-8").splitlines()]
    assert index_entries[-1]["request_id"] == response.request_id
    assert index_entries[-1]["dq_status"] == "fail"


def test_generate_chat_reply_quarantines_validation_fail(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = _FakeSettings(str(tmp_path))
    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_service,
        "_generate_provider_result",
        lambda **kwargs: _provider_result(text="\0\u200b \t\n", request_id=kwargs["request_id"]),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    assert response.error_type == "validation_failed"
    assert response.text.startswith("目前 AI 回覆格式異常，請稍後再試。request_id=")

    snapshot_dir = tmp_path / response.request_id
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
    tmp_path: Path,
) -> None:
    settings = _FakeSettings(str(tmp_path))
    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_service,
        "_generate_provider_result",
        lambda **kwargs: (_ for _ in ()).throw(
            chat_service._ProviderDispatchError(
                "provider_not_ready",
                "not ready",
                request_json={"model": settings.ai_model, "messages": kwargs["messages"]},
            )
        ),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=None)

    snapshot_dir = tmp_path / response.request_id
    assert not (snapshot_dir / "staging_record.json").exists()
    assert not (snapshot_dir / "quarantine_entry.json").exists()

    meta = json.loads((snapshot_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["staging_status"] == "skipped"
    assert meta["quarantine_status"] == "not_applicable"


def test_chat_staging_inspect_cli_supports_request_and_quarantine_listing(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    monkeypatch.setattr(
        chat_staging_inspect,
        "get_ai_settings",
        lambda: SimpleNamespace(ai_raw_snapshot_dir=str(tmp_path)),
    )

    staged_dir = tmp_path / "req-staged"
    staged_dir.mkdir()
    (staged_dir / "meta.json").write_text('{"request_id":"req-staged"}', encoding="utf-8")
    (staged_dir / "staging_record.json").write_text(
        json.dumps({"request_id": "req-staged"}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    quarantined_dir = tmp_path / "req-quarantine"
    quarantined_dir.mkdir()
    (quarantined_dir / "meta.json").write_text('{"request_id":"req-quarantine"}', encoding="utf-8")
    (quarantined_dir / "quarantine_entry.json").write_text(
        json.dumps({"request_id": "req-quarantine"}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    quarantine_index = tmp_path / "_quarantine" / "quarantine_index.jsonl"
    quarantine_index.parent.mkdir(parents=True, exist_ok=True)
    quarantine_index.write_text(
        json.dumps({"request_id": "req-quarantine"}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    assert chat_staging_inspect.main(["--request-id", "req-staged"]) == 0
    staged_payload = json.loads(capsys.readouterr().out)
    assert staged_payload["staging_record"] == {"request_id": "req-staged"}

    assert chat_staging_inspect.main(["--request-id", "req-quarantine"]) == 0
    quarantine_payload = json.loads(capsys.readouterr().out)
    assert quarantine_payload["quarantine_entry"] == {"request_id": "req-quarantine"}

    assert chat_staging_inspect.main(["--request-id", "missing"]) == 2
    capsys.readouterr()

    assert chat_staging_inspect.main(["--list-quarantine", "--limit", "5"]) == 0
    listed_payload = json.loads(capsys.readouterr().out)
    assert listed_payload["entries"] == [{"request_id": "req-quarantine"}]
