# backend/tests/test_chat_service_demand_resolution.py
from types import SimpleNamespace

import backend.services.chat.provider_caller as chat_provider_caller
import backend.services.chat.service as chat_service
from backend.services.chat.contracts import ChatRequest


class _FakeSettings:
    ai_oai_base_url = "https://example.invalid/v1"
    ai_oai_api_key = None
    ai_model = "gpt-4o-mini"
    ai_timeout_seconds = 10.0
    ai_max_output_chars = 4000
    ai_provider = "openai_compat"
    p2_max_value_len = 120
    p2_max_specs_per_part = 12
    p2_spec_whitelist_by_category = {}


def _sample_compressed_candidates() -> dict[str, list[dict[str, object]]]:
    return {
        "CPU": [
            {
                "part_id": "cpu-1",
                "category": "CPU",
                "display_name": "CPU 1",
                "key_specs": {},
                "price": 1000,
                "source": "coolpc",
                "source_url": "https://example.invalid/cpu-1",
                "run_id": "run-1",
            }
        ]
    }


def _provider_result(
    *,
    request_id: str,
    messages: list[dict[str, str]],
    text: str,
) -> chat_provider_caller.ProviderCallResult:
    return chat_provider_caller.ProviderCallResult(
        text=text,
        endpoint="https://example.invalid/v1/chat/completions",
        status_code=200,
        request_headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Client-Request-Id": request_id,
        },
        request_json={"model": "gpt-4o-mini", "messages": messages},
        response_headers={"x-request-id": "up-1"},
        response_json={"choices": [{"message": {"content": text}}]},
        raw_response_text='{"choices":[{"message":{"content":"ok"}}]}',
        upstream_request_id="up-1",
    )


def test_generate_chat_reply_prefers_explicit_demand(monkeypatch) -> None:
    captured_retrieve: dict[str, object] = {}
    captured_provider: dict[str, object] = {}
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: _FakeSettings())
    monkeypatch.setattr(
        chat_service,
        "infer_chat_demand",
        lambda message, history=None: {"categories": ["GPU"], "top_k": 2, "env": "prod"},
    )

    def fake_retrieve(*args, **kwargs):
        captured_retrieve.update(kwargs)
        return object()

    monkeypatch.setattr(chat_service, "retrieve_topk_candidates", fake_retrieve)
    monkeypatch.setattr(
        chat_service,
        "compress_candidates",
        lambda *args, **kwargs: (_sample_compressed_candidates(), {}),
    )
    monkeypatch.setattr(
        chat_service,
        "build_context_pack",
        lambda **kwargs: SimpleNamespace(text="ctx", hash="ctx-hash"),
    )
    def fake_provider_call(**kwargs):
        captured_provider.update(kwargs)
        return _provider_result(
            request_id=kwargs["request_id"],
            messages=kwargs["messages"],
            text="這是一段正常且足夠長的建議內容，包含 CPU 1 的文書機配置建議。",
        )

    monkeypatch.setattr(chat_provider_caller, "generate_provider_result", fake_provider_call)
    monkeypatch.setattr(
        chat_service,
        "log_operation",
        lambda event, **fields: events.append((event, fields)),
    )
    monkeypatch.setattr(chat_service, "_persist_ai_snapshot", lambda **kwargs: "file:test")

    response = chat_service.generate_chat_reply(
        ChatRequest(
            user_text="幫我配一台電腦",
            demand={"categories": ["CPU"], "top_k": 2, "env": "prod"},
        ),
        db=object(),
    )

    assert response.text == "這是一段正常且足夠長的建議內容，包含 CPU 1 的文書機配置建議。"
    assert captured_retrieve["categories"] == ["CPU"]
    assert captured_provider["request_id"] == response.request_id

    demand_events = [fields for event, fields in events if event == "demand_resolution"]
    assert len(demand_events) == 1
    assert demand_events[0]["source"] == "explicit"
    assert demand_events[0]["categories"] == "CPU"
    assert demand_events[0]["triggered_retrieval"] is True


def test_generate_chat_reply_uses_inferred_demand_for_context_pack(monkeypatch) -> None:
    captured_retrieve: dict[str, object] = {}
    captured_provider: dict[str, object] = {}
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: _FakeSettings())
    monkeypatch.setattr(
        chat_service,
        "infer_chat_demand",
        lambda message, history=None: {"categories": ["CPU"], "top_k": 2, "env": "prod"},
    )

    def fake_retrieve(*args, **kwargs):
        captured_retrieve.update(kwargs)
        return object()

    monkeypatch.setattr(chat_service, "retrieve_topk_candidates", fake_retrieve)
    monkeypatch.setattr(
        chat_service,
        "compress_candidates",
        lambda *args, **kwargs: (_sample_compressed_candidates(), {}),
    )
    monkeypatch.setattr(
        chat_service,
        "build_context_pack",
        lambda **kwargs: SimpleNamespace(text="CTX BODY", hash="ctx-hash"),
    )

    def fake_provider_call(**kwargs):
        captured_provider.update(kwargs)
        return _provider_result(
            request_id=kwargs["request_id"],
            messages=kwargs["messages"],
            text="建議先看 CPU 1，這是一段正常且足夠長的文書機配置建議內容。",
        )

    monkeypatch.setattr(chat_provider_caller, "generate_provider_result", fake_provider_call)
    monkeypatch.setattr(
        chat_service,
        "log_operation",
        lambda event, **fields: events.append((event, fields)),
    )
    monkeypatch.setattr(chat_service, "_persist_ai_snapshot", lambda **kwargs: "file:test")

    response = chat_service.generate_chat_reply(
        ChatRequest(user_text="幫我推薦 2 萬內文書機"),
        db=object(),
    )

    assert response.text == "建議先看 CPU 1，這是一段正常且足夠長的文書機配置建議內容。"
    assert response.compressed_candidates is not None
    assert captured_retrieve["categories"] == ["CPU"]
    user_messages = [m["content"] for m in captured_provider["messages"] if m["role"] == "user"]
    assert any("## CONTEXT_PACK" in content for content in user_messages)

    demand_events = [fields for event, fields in events if event == "demand_resolution"]
    assert len(demand_events) == 1
    assert demand_events[0]["source"] == "inferred"
    assert demand_events[0]["triggered_retrieval"] is True

    ai_events = [fields for event, fields in events if event == "ai_call"]
    assert len(ai_events) == 1
    assert ai_events[0]["context_pack_hash"] == "ctx-hash"


def test_generate_chat_reply_keeps_generic_chat_when_inference_returns_none(monkeypatch) -> None:
    captured_provider: dict[str, object] = {}
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: _FakeSettings())
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda message, history=None: None)
    monkeypatch.setattr(
        chat_service,
        "retrieve_topk_candidates",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("retrieval should not run")),
    )

    def fake_provider_call(**kwargs):
        captured_provider.update(kwargs)
        return _provider_result(
            request_id=kwargs["request_id"],
            messages=kwargs["messages"],
            text="這是一段正常且足夠長的通用聊天回覆，不需要額外 context pack。",
        )

    monkeypatch.setattr(chat_provider_caller, "generate_provider_result", fake_provider_call)
    monkeypatch.setattr(
        chat_service,
        "log_operation",
        lambda event, **fields: events.append((event, fields)),
    )
    monkeypatch.setattr(chat_service, "_persist_ai_snapshot", lambda **kwargs: "file:test")

    response = chat_service.generate_chat_reply(
        ChatRequest(user_text="你好"),
        db=object(),
    )

    assert response.text == "這是一段正常且足夠長的通用聊天回覆，不需要額外 context pack。"
    assert response.compressed_candidates == {}
    assert response.drop_log == {}
    user_messages = [m["content"] for m in captured_provider["messages"] if m["role"] == "user"]
    assert user_messages
    assert all("## CONTEXT_PACK" not in content for content in user_messages)

    demand_events = [fields for event, fields in events if event == "demand_resolution"]
    assert len(demand_events) == 1
    assert demand_events[0]["source"] == "none"
    assert demand_events[0]["triggered_retrieval"] is False

    ai_events = [fields for event, fields in events if event == "ai_call"]
    assert len(ai_events) == 1
    assert ai_events[0]["context_pack_hash"] == "-"
