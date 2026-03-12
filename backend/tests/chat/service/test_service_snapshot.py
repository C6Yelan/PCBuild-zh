# backend/tests/chat/service/test_service_snapshot.py
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import backend.services.chat.provider_caller as chat_provider_caller
import backend.services.chat.service as chat_service
from backend.services.chat.contracts import ChatRequest


def _sample_candidates() -> dict[str, list[dict[str, object]]]:
    return {
        "CPU": [
            {
                "part_id": "cpu-1",
                "category": "CPU",
                "display_name": "CPU 1",
                "key_specs": {"socket_hint": "AM4"},
                "price": 1000,
                "source": "coolpc",
                "source_url": "https://example.invalid/cpu-1",
                "snapshot_id": None,
                "run_id": "run-1",
            }
        ],
        "MB": [
            {
                "part_id": "mb-1",
                "category": "MB",
                "display_name": "MB 1",
                "key_specs": {"socket_hint": "AM4"},
                "price": 2000,
                "source": "coolpc",
                "source_url": "https://example.invalid/mb-1",
                "snapshot_id": "snap-1",
                "run_id": None,
            }
        ],
    }


def test_snapshot_writes_extended_artifacts_with_retrieval(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir)
    compressed_candidates = _sample_candidates()
    drop_log = {
        "cpu-1": {
            "dropped_fields": [],
            "dropped_specs": [],
            "truncated_specs": {},
            "reason": ["fallback_used"],
        }
    }

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "retrieve_topk_candidates", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        chat_service,
        "compress_candidates",
        lambda *args, **kwargs: (compressed_candidates, drop_log),
    )
    monkeypatch.setattr(
        chat_service,
        "build_context_pack",
        lambda **kwargs: SimpleNamespace(text="CTX BODY", hash="ctx-hash"),
    )
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: provider_result_factory(
            request_id=kwargs["request_id"],
            text="建議選 CPU 1 搭配 MB 1，這樣的處理器與主機板組合比較穩定。",
            request_headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": "Bearer secret-value",
                "X-Client-Request-Id": kwargs["request_id"],
                "x-api-key": "top-secret",
            },
            request_json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hi"}],
                "api_key": "never-log-me",
            },
        ),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(
        ChatRequest(
            user_text="幫我配一台文書機",
            demand={"categories": ["CPU", "MB"], "top_k": 2, "env": "prod"},
        ),
        db=object(),
    )

    snapshot_dir = snapshot_temp_dir / response.request_id
    assert (snapshot_dir / "raw_request.json").exists()
    assert (snapshot_dir / "raw_response.json").exists()
    assert (snapshot_dir / "meta.json").exists()
    assert (snapshot_dir / "context_pack.txt").exists()
    assert (snapshot_dir / "compressed_candidates.json").exists()
    assert (snapshot_dir / "drop_log.json").exists()
    assert (snapshot_dir / "request_context.json").exists()
    assert (snapshot_dir / "validation_report.json").exists()
    assert (snapshot_dir / "dq_report.json").exists()
    assert (snapshot_dir / "lineage.json").exists()
    assert (snapshot_dir / "staging_record.json").exists()
    assert not (snapshot_dir / "quarantine_entry.json").exists()

    request_context = json.loads(
        (snapshot_dir / "request_context.json").read_text(encoding="utf-8")
    )
    assert request_context["demand_source"] == "explicit"
    assert request_context["triggered_retrieval"] is True
    assert request_context["categories"] == ["CPU", "MB"]
    assert request_context["top_k"] == 2
    assert request_context["env"] == "prod"
    assert request_context["has_context_pack"] is True

    lineage = json.loads((snapshot_dir / "lineage.json").read_text(encoding="utf-8"))
    assert lineage == {
        "request_id": response.request_id,
        "context_pack_hash": "ctx-hash",
        "categories": {
            "CPU": [
                {
                    "part_id": "cpu-1",
                    "category": "CPU",
                    "display_name": "CPU 1",
                    "source": "coolpc",
                    "source_url": "https://example.invalid/cpu-1",
                    "snapshot_id": None,
                    "run_id": "run-1",
                }
            ],
            "MB": [
                {
                    "part_id": "mb-1",
                    "category": "MB",
                    "display_name": "MB 1",
                    "source": "coolpc",
                    "source_url": "https://example.invalid/mb-1",
                    "snapshot_id": "snap-1",
                    "run_id": None,
                }
            ],
        },
    }

    meta = json.loads((snapshot_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["upstream_request_id"] == "up-1"
    assert meta["status_code"] == 200
    assert meta["request_mode"] == "user_text"
    assert meta["demand_source"] == "explicit"
    assert meta["triggered_retrieval"] is True
    assert meta["gate_status"] == "pass"
    assert meta["gate_reasons"] == []
    assert meta["dq_status"] == "pass"
    assert meta["dq_reasons"] == []
    assert meta["staging_status"] == "staged"
    assert meta["quarantine_status"] == "not_quarantined"
    assert meta["artifacts"] == [
        "raw_request.json",
        "raw_response.json",
        "request_context.json",
        "validation_report.json",
        "dq_report.json",
        "context_pack.txt",
        "compressed_candidates.json",
        "drop_log.json",
        "lineage.json",
        "staging_record.json",
        "meta.json",
    ]
    staging_record = json.loads((snapshot_dir / "staging_record.json").read_text(encoding="utf-8"))
    assert staging_record["published"] is True
    assert staging_record["publish_blocked"] is False
    assert staging_record["publish_reason"] == "staged_pass"
    assert staging_record["data_versions"] == lineage["categories"]

    raw_request = json.loads((snapshot_dir / "raw_request.json").read_text(encoding="utf-8"))
    assert raw_request["request_headers"]["Authorization"] == "[REDACTED]"
    assert raw_request["request_headers"]["x-api-key"] == "[REDACTED]"
    assert raw_request["request_json"]["api_key"] == "[REDACTED]"


def test_snapshot_writes_minimal_artifacts_without_retrieval(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir)

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_service,
        "retrieve_topk_candidates",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("retrieval should not run")),
    )
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: provider_result_factory(request_id=kwargs["request_id"]),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=object())

    snapshot_dir = snapshot_temp_dir / response.request_id
    assert (snapshot_dir / "raw_request.json").exists()
    assert (snapshot_dir / "raw_response.json").exists()
    assert (snapshot_dir / "meta.json").exists()
    assert (snapshot_dir / "request_context.json").exists()
    assert (snapshot_dir / "validation_report.json").exists()
    assert (snapshot_dir / "dq_report.json").exists()
    assert (snapshot_dir / "staging_record.json").exists()
    assert not (snapshot_dir / "quarantine_entry.json").exists()
    assert not (snapshot_dir / "context_pack.txt").exists()
    assert not (snapshot_dir / "compressed_candidates.json").exists()
    assert not (snapshot_dir / "drop_log.json").exists()
    assert not (snapshot_dir / "lineage.json").exists()

    request_context = json.loads(
        (snapshot_dir / "request_context.json").read_text(encoding="utf-8")
    )
    assert request_context["demand_source"] == "none"
    assert request_context["triggered_retrieval"] is False
    assert request_context["categories"] == []

    meta = json.loads((snapshot_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta["gate_status"] == "pass"
    assert meta["gate_reasons"] == []
    assert meta["dq_status"] == "pass"
    assert meta["dq_reasons"] == []
    assert meta["staging_status"] == "staged"
    assert meta["quarantine_status"] == "not_quarantined"
    assert meta["artifacts"] == [
        "raw_request.json",
        "raw_response.json",
        "request_context.json",
        "validation_report.json",
        "dq_report.json",
        "staging_record.json",
        "meta.json",
    ]
    staging_record = json.loads((snapshot_dir / "staging_record.json").read_text(encoding="utf-8"))
    assert staging_record["published"] is True
    assert staging_record["publish_blocked"] is False
    assert staging_record["publish_reason"] == "staged_pass"
    assert staging_record["data_versions"] == {}


def test_snapshot_request_context_reflects_truncation_warning(
    monkeypatch,
    snapshot_temp_dir: Path,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    settings = fake_chat_settings(raw_snapshot_dir=snapshot_temp_dir, max_output_chars=5)

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_provider_caller,
        "generate_provider_result",
        lambda **kwargs: provider_result_factory(
            request_id=kwargs["request_id"],
            text="abcdefghij",
            messages=kwargs["messages"],
        ),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(
        ChatRequest(user_text="請回一段很長的內容"),
        db=object(),
    )

    assert response.text == "abcde"
    assert response.warnings is not None
    assert "output_truncated" in response.warnings

    snapshot_dir = snapshot_temp_dir / response.request_id
    request_context = json.loads(
        (snapshot_dir / "request_context.json").read_text(encoding="utf-8")
    )
    assert "output_truncated" in request_context["warnings"]
    validation_report = json.loads(
        (snapshot_dir / "validation_report.json").read_text(encoding="utf-8")
    )
    assert validation_report["passed"] is True
    assert validation_report["reasons"] == []
    dq_report = json.loads((snapshot_dir / "dq_report.json").read_text(encoding="utf-8"))
    assert dq_report["passed"] is True
    assert dq_report["reasons"] == []
