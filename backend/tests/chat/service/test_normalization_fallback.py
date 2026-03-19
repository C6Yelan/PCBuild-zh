from __future__ import annotations

from types import SimpleNamespace

from backend.services.chat.contracts import ChatMessage
from backend.services.chat.service.normalization import run_normalization_pass


def _settings() -> object:
    return SimpleNamespace(ai_provider="openai_compat", ai_model="test-model")


def test_normalization_pass_uses_repair_when_json_is_invalid(provider_result_factory) -> None:
    calls: list[str] = []

    def fake_provider(**kwargs):
        calls.append(kwargs["request_id"])
        if kwargs["request_id"].endswith(":structured"):
            raise RuntimeError("structured unsupported")
        if kwargs["request_id"].endswith(":json"):
            return provider_result_factory(
                request_id=kwargs["request_id"],
                text='{"request_mode":"single_part","categories":["GPU",],"query_focus":["RTX 5070"]}',
            )
        raise AssertionError("repair pass should not run")

    result = run_normalization_pass(
        message_text="幫我找 2 萬左右的 RTX 5070 顯卡",
        history=[ChatMessage(role="user", content="之前先看過 4070")],
        explicit_demand=None,
        settings=_settings(),
        request_id="req-1",
        generate_provider_result=fake_provider,
        log_operation=lambda *args, **kwargs: None,
    )

    assert result.normalized_demand.request_mode == "single_part"
    assert result.normalized_demand.categories == ["GPU"]
    assert result.normalized_demand.normalization_source == "ai_repaired_json"
    assert result.fallback_used is True
    assert calls == ["req-1:normalize:structured", "req-1:normalize:json"]


def test_normalization_pass_falls_back_to_rules_when_provider_keeps_failing() -> None:
    result = run_normalization_pass(
        message_text="最近有推薦的 Ryzen 9700X CPU 嗎",
        history=None,
        explicit_demand=None,
        settings=_settings(),
        request_id="req-2",
        generate_provider_result=lambda **kwargs: (_ for _ in ()).throw(RuntimeError("provider down")),
        log_operation=lambda *args, **kwargs: None,
    )

    assert result.normalized_demand.request_mode == "single_part"
    assert result.normalized_demand.categories == ["CPU"]
    assert "Ryzen 9700X" in result.normalized_demand.query_focus
    assert result.normalized_demand.normalization_source == "rule_fallback"
    assert result.fallback_used is True
