# backend/tests/chat/service/test_service_retrieval_failure.py
import backend.services.chat.service as chat_service
from backend.services.chat.contracts import ChatRequest


def test_generate_chat_reply_keeps_running_when_p1_retrieval_fails(
    monkeypatch,
    fake_chat_settings,
) -> None:
    events: list[tuple[str, dict[str, object]]] = []

    def fake_retrieve_topk_candidates(*args, **kwargs):
        raise RuntimeError("p1 unavailable")

    def fake_generate_openai_compat_text(**kwargs):
        return "fixed-response"

    def fake_log_operation(event: str, **fields):
        events.append((event, fields))

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: fake_chat_settings())
    monkeypatch.setattr(chat_service, "retrieve_topk_candidates", fake_retrieve_topk_candidates)
    monkeypatch.setattr(chat_service, "generate_openai_compat_text", fake_generate_openai_compat_text)
    monkeypatch.setattr(chat_service, "log_operation", fake_log_operation)

    request = ChatRequest(
        user_text="幫我配電腦",
        demand={
            "categories": ["CPU"],
            "top_k": 2,
            "env": "prod",
        },
    )

    response = chat_service.generate_chat_reply(request, db=object())
    assert response.text.startswith("目前資料不足，請補充需求後再試。request_id=")
    assert response.error_type == "dq_failed"
    assert response.warnings is not None
    assert "p1_retrieval_failed" in response.warnings
    failure_events = [fields for event, fields in events if event == "p1_retrieval_failed"]
    assert len(failure_events) == 1
    assert failure_events[0] == {
        "error_type": "RuntimeError",
        "env": "prod",
        "categories": "CPU",
        "top_k": 2,
    }
    ai_events = [fields for event, fields in events if event == "ai_call"]
    assert len(ai_events) == 1
    assert ai_events[0]["provider"] == "openai_compat"
    assert ai_events[0]["model"] == "gpt-4o-mini"
    assert ai_events[0]["ok"] is False
    assert ai_events[0]["error_type"] == "dq_failed"
    assert ai_events[0]["gate_status"] == "pass"
    assert ai_events[0]["dq_status"] == "fail"
    assert ai_events[0]["staging_status"] == "skipped"
    assert ai_events[0]["quarantine_status"] == "quarantined"
