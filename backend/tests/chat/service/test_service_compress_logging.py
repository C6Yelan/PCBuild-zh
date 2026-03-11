# backend/tests/chat/service/test_service_compress_logging.py
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


def test_generate_chat_reply_emits_p2_compress_log(monkeypatch) -> None:
    events: list[tuple[str, dict[str, object]]] = []

    compressed_candidates = {
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
        ],
        "GPU": [
            {
                "part_id": "gpu-1",
                "category": "GPU",
                "display_name": "GPU 1",
                "key_specs": {},
                "price": 2000,
                "source": "coolpc",
                "source_url": "https://example.invalid/gpu-1",
                "run_id": "run-2",
            }
        ],
    }
    drop_log = {
        "cpu-1": {
            "dropped_fields": [],
            "dropped_specs": ["foo"],
            "truncated_specs": {},
            "reason": ["fallback_used"],
        },
        "gpu-1": {
            "dropped_fields": [],
            "dropped_specs": [],
            "truncated_specs": {"name": {"orig_len": 20, "new_len": 10}},
            "reason": ["not_whitelisted"],
        },
    }

    monkeypatch.setattr(chat_service, "get_ai_settings", lambda: _FakeSettings())
    monkeypatch.setattr(chat_service, "retrieve_topk_candidates", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        chat_service,
        "compress_candidates",
        lambda *args, **kwargs: (compressed_candidates, drop_log),
    )
    monkeypatch.setattr(
        chat_service,
        "generate_openai_compat_text",
        lambda **kwargs: "建議選 CPU 1 搭配 GPU 1。",
    )
    monkeypatch.setattr(
        chat_service,
        "log_operation",
        lambda event, **fields: events.append((event, fields)),
    )

    request = ChatRequest(
        user_text="幫我配電腦",
        demand={
            "categories": ["CPU", "GPU"],
            "top_k": 2,
            "env": "prod",
        },
    )

    response = chat_service.generate_chat_reply(request, db=object())
    dumped = response.model_dump()
    assert response.text == "建議選 CPU 1 搭配 GPU 1。"
    assert dumped["compressed_candidates"] == {
        "CPU": [
            {
                "part_id": "cpu-1",
                "category": "CPU",
                "display_name": "CPU 1",
                "key_specs": {},
                "price": 1000.0,
                "source": "coolpc",
                "source_url": "https://example.invalid/cpu-1",
                "snapshot_id": None,
                "run_id": "run-1",
            }
        ],
        "GPU": [
            {
                "part_id": "gpu-1",
                "category": "GPU",
                "display_name": "GPU 1",
                "key_specs": {},
                "price": 2000.0,
                "source": "coolpc",
                "source_url": "https://example.invalid/gpu-1",
                "snapshot_id": None,
                "run_id": "run-2",
            }
        ],
    }
    assert dumped["drop_log"] == drop_log

    p2_events = [fields for event, fields in events if event == "p2_compress"]
    assert len(p2_events) == 1
    assert p2_events[0] == {
        "env": "prod",
        "top_k": 2,
        "requested_categories": "CPU,GPU",
        "returned_categories": "CPU,GPU",
        "returned_count": 2,
        "drop_log_count": 2,
        "fallback_count": 1,
        "dropped_specs_count": 1,
        "truncated_specs_count": 1,
        "max_value_len": 120,
        "max_specs_per_part": 12,
    }
