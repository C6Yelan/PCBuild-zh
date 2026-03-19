# backend/tests/chat/service/test_service_demand_resolution.py
from types import SimpleNamespace

import backend.services.chat.provider_caller as chat_provider_caller
import backend.services.chat.service as chat_service
import backend.services.chat.snapshot_store as chat_snapshot_store
from backend.services.chat.contracts import ChatRequest
from backend.services.chat.service.demand import resolve_demand


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


def test_generate_chat_reply_prefers_explicit_demand(
    monkeypatch,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    captured_retrieve: dict[str, object] = {}
    captured_provider: dict[str, object] = {}
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: fake_chat_settings())
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
        return provider_result_factory(
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
    monkeypatch.setattr(chat_snapshot_store, "persist_ai_snapshot", lambda **kwargs: "file:test")

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


def test_generate_chat_reply_uses_inferred_demand_for_context_pack(
    monkeypatch,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    captured_retrieve: dict[str, object] = {}
    captured_provider: dict[str, object] = {}
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: fake_chat_settings())
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
        return provider_result_factory(
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
    monkeypatch.setattr(chat_snapshot_store, "persist_ai_snapshot", lambda **kwargs: "file:test")

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


def test_generate_chat_reply_keeps_generic_chat_when_inference_returns_none(
    monkeypatch,
    fake_chat_settings,
    provider_result_factory,
) -> None:
    captured_provider: dict[str, object] = {}
    events: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: fake_chat_settings())
    monkeypatch.setattr(chat_service, "infer_chat_demand", lambda message, history=None: None)
    monkeypatch.setattr(
        chat_service,
        "retrieve_topk_candidates",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("retrieval should not run")),
    )

    def fake_provider_call(**kwargs):
        captured_provider.update(kwargs)
        return provider_result_factory(
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
    monkeypatch.setattr(chat_snapshot_store, "persist_ai_snapshot", lambda **kwargs: "file:test")

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


def test_resolve_demand_preserves_budget_filters_for_retrieval() -> None:
    demand = resolve_demand(
        ChatRequest(
            user_text="幫我找零件",
            demand={
                "categories": ["GPU"],
                "filters": {
                    "budget": 20000,
                    "target_price": 18000,
                },
            },
        ),
        infer_chat_demand=lambda message, history=None: None,
    )

    assert demand.top_k == 5
    assert demand.retrieval_demand is not None
    assert demand.retrieval_demand.budget == 20000
    assert demand.retrieval_demand.max_price == 20000
    assert demand.retrieval_demand.target_price == 18000
