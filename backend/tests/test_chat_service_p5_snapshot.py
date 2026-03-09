# backend/tests/test_chat_service_p5_snapshot.py
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import backend.services.chat.service as chat_service
import backend.tools.ops.chat_snapshot_inspect as chat_snapshot_inspect
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


def _provider_result(request_id: str) -> chat_service._ProviderCallResult:
    return chat_service._ProviderCallResult(
        text="ok",
        endpoint="https://example.invalid/v1/chat/completions",
        status_code=200,
        request_headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "Bearer secret-value",
            "X-Client-Request-Id": request_id,
            "x-api-key": "top-secret",
        },
        request_json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hi"}],
            "api_key": "never-log-me",
        },
        response_headers={"x-request-id": "up-1"},
        response_json={"choices": [{"message": {"content": "ok"}}]},
        raw_response_text='{"choices":[{"message":{"content":"ok"}}]}',
        upstream_request_id="up-1",
    )


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
    tmp_path: Path,
) -> None:
    settings = _FakeSettings(str(tmp_path))
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
        chat_service,
        "_generate_provider_result",
        lambda **kwargs: _provider_result(kwargs["request_id"]),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(
        ChatRequest(
            user_text="幫我配一台文書機",
            demand={"categories": ["CPU", "MB"], "top_k": 2, "env": "prod"},
        ),
        db=object(),
    )

    snapshot_dir = tmp_path / response.request_id
    assert (snapshot_dir / "raw_request.json").exists()
    assert (snapshot_dir / "raw_response.json").exists()
    assert (snapshot_dir / "meta.json").exists()
    assert (snapshot_dir / "context_pack.txt").exists()
    assert (snapshot_dir / "compressed_candidates.json").exists()
    assert (snapshot_dir / "drop_log.json").exists()
    assert (snapshot_dir / "request_context.json").exists()
    assert (snapshot_dir / "lineage.json").exists()

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
    assert meta["artifacts"] == [
        "raw_request.json",
        "raw_response.json",
        "request_context.json",
        "context_pack.txt",
        "compressed_candidates.json",
        "drop_log.json",
        "lineage.json",
        "meta.json",
    ]

    raw_request = json.loads((snapshot_dir / "raw_request.json").read_text(encoding="utf-8"))
    assert raw_request["request_headers"]["Authorization"] == "[REDACTED]"
    assert raw_request["request_headers"]["x-api-key"] == "[REDACTED]"
    assert raw_request["request_json"]["api_key"] == "[REDACTED]"


def test_snapshot_writes_minimal_artifacts_without_retrieval(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = _FakeSettings(str(tmp_path))

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_service,
        "retrieve_topk_candidates",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("retrieval should not run")),
    )
    monkeypatch.setattr(
        chat_service,
        "_generate_provider_result",
        lambda **kwargs: _provider_result(kwargs["request_id"]),
    )
    monkeypatch.setattr(chat_service, "log_operation", lambda *args, **kwargs: None)

    response = chat_service.generate_chat_reply(ChatRequest(user_text="你好"), db=object())

    snapshot_dir = tmp_path / response.request_id
    assert (snapshot_dir / "raw_request.json").exists()
    assert (snapshot_dir / "raw_response.json").exists()
    assert (snapshot_dir / "meta.json").exists()
    assert (snapshot_dir / "request_context.json").exists()
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
    assert meta["artifacts"] == [
        "raw_request.json",
        "raw_response.json",
        "request_context.json",
        "meta.json",
    ]


def test_snapshot_request_context_reflects_truncation_warning(
    monkeypatch,
    tmp_path: Path,
) -> None:
    settings = _FakeSettings(str(tmp_path))
    settings.ai_max_output_chars = 5

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: settings)
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        chat_service,
        "_generate_provider_result",
        lambda **kwargs: chat_service._ProviderCallResult(
            text="abcdefghij",
            endpoint="https://example.invalid/v1/chat/completions",
            status_code=200,
            request_headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Client-Request-Id": kwargs["request_id"],
            },
            request_json={"model": "gpt-4o-mini", "messages": kwargs["messages"]},
            response_headers={"x-request-id": "up-1"},
            response_json={"choices": [{"message": {"content": "abcdefghij"}}]},
            raw_response_text='{"choices":[{"message":{"content":"abcdefghij"}}]}',
            upstream_request_id="up-1",
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

    snapshot_dir = tmp_path / response.request_id
    request_context = json.loads(
        (snapshot_dir / "request_context.json").read_text(encoding="utf-8")
    )
    assert "output_truncated" in request_context["warnings"]


def test_chat_snapshot_inspect_cli_exit_codes(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setattr(
        chat_snapshot_inspect,
        "get_ai_settings",
        lambda: SimpleNamespace(ai_raw_snapshot_dir=str(tmp_path)),
    )

    ok_dir = tmp_path / "req-ok"
    ok_dir.mkdir()
    for filename, payload in {
        "raw_request.json": {"ok": True},
        "raw_response.json": {"ok": True},
        "meta.json": {"request_id": "req-ok"},
        "request_context.json": {"request_id": "req-ok"},
        "lineage.json": {"request_id": "req-ok"},
    }.items():
        (ok_dir / filename).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    incomplete_dir = tmp_path / "req-missing"
    incomplete_dir.mkdir()
    for filename, payload in {
        "raw_request.json": {"ok": True},
        "raw_response.json": {"ok": True},
        "meta.json": {"request_id": "req-missing"},
    }.items():
        (incomplete_dir / filename).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    assert chat_snapshot_inspect.main(["--request-id", "req-ok"]) == 0
    capsys.readouterr()
    assert chat_snapshot_inspect.main(["--request-id", "req-missing"]) == 1
    capsys.readouterr()
    assert chat_snapshot_inspect.main(["--request-id", "req-404"]) == 2
