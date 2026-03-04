# backend/tests/test_chat_service_p1_failure.py
import backend.services.chat.service as chat_service
from backend.services.chat.contracts import ChatRequest


class _FakeSettings:
    ai_oai_base_url = "https://example.invalid/v1"
    ai_oai_api_key = None
    ai_model = "gpt-4o-mini"
    ai_timeout_seconds = 10.0
    ai_max_output_chars = 4000
    ai_provider = "openai_compat"


def test_generate_chat_reply_keeps_running_when_p1_retrieval_fails(
    monkeypatch,
) -> None:
    logged: dict[str, object] = {}

    def fake_retrieve_topk_candidates(*args, **kwargs):
        raise RuntimeError("p1 unavailable")

    def fake_generate_openai_compat_text(**kwargs):
        return "fixed-response"

    def fake_log_operation(event: str, **fields):
        logged["event"] = event
        logged["fields"] = fields

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: _FakeSettings())
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
    assert response.text == "fixed-response"
    assert response.warnings is not None
    assert "p1_retrieval_failed" in response.warnings
    assert logged["event"] == "p1_retrieval_failed"
    assert logged["fields"] == {
        "error_type": "RuntimeError",
        "env": "prod",
        "categories": "CPU",
        "top_k": 2,
    }
