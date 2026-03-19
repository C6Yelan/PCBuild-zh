from __future__ import annotations

from backend.services.chat.build_policy import BuildRequestProfile
from backend.services.chat.contracts import ChatRequest, NormalizedDemand
from backend.services.chat.provider.caller import build_provider_messages


def test_build_provider_messages_includes_normalized_demand_and_clean_context_pack() -> None:
    messages = build_provider_messages(
        ChatRequest(user_text="幫我找 2 萬左右的 RTX 5070 顯卡"),
        context_pack_text="=== GPU CANDIDATES ===\n[GPU#gpu-1] RTX 5070 | price_twd=19990",
        context_pack_meta={"counts": {"GPU": 1}},
        normalized_demand=NormalizedDemand.model_validate(
            {
                "request_mode": "single_part",
                "categories": ["GPU"],
                "budget_target": 20000,
                "query_focus": ["RTX 5070"],
                "normalization_source": "ai_structured",
            }
        ),
        build_profile=BuildRequestProfile(enabled=False, request_mode="single_part"),
    )

    user_payload = messages[-1]["content"]
    assert "## NORMALIZED_DEMAND" in user_payload
    assert '"request_mode": "single_part"' in user_payload
    assert "## CONTEXT_PACK" in user_payload
    assert "clean_context_pack=true" in user_payload
    assert "不可轉成整機 build" in user_payload
    assert "## BUILD_SCORING" not in user_payload


def test_build_provider_messages_keeps_build_budget_guardrail() -> None:
    messages = build_provider_messages(
        ChatRequest(user_text="幫我配一台 4 萬內遊戲機"),
        context_pack_text="=== CPU CANDIDATES ===\n[CPU#cpu-1] Ryzen 7 9700X",
        context_pack_meta={
            "counts": {"CPU": 1, "MB": 0, "GPU": 0},
            "build_scoring": {
                "build_profile": "build",
                "usage_profile": "gaming",
                "target_total_price": 38000,
                "minimum_budget_utilization": 36000,
                "selected_build": {
                    "assessment": "這是一組整體分配合理的 gaming build。",
                    "total_build_price": 37950,
                    "score_breakdown": {
                        "cpu_gpu_balance_score": 92.0,
                        "motherboard_tier_match_score": 88.0,
                        "budget_utilization_score": 95.0,
                    },
                },
            },
        },
        normalized_demand=NormalizedDemand.model_validate(
            {
                "request_mode": "build",
                "categories": ["CPU", "MB", "RAM", "SSD", "PSU", "CASE", "GPU"],
                "budget_max": 40000,
                "normalization_source": "ai_structured",
            }
        ),
        build_profile=BuildRequestProfile(
            enabled=True,
            request_mode="build",
            minimum_budget_utilization=36000,
        ),
    )

    user_payload = messages[-1]["content"]
    assert "整機 build 需求" in user_payload
    assert "36000" in user_payload
    assert "CPU:1" in user_payload
    assert "## BUILD_SCORING" in user_payload
    assert '"selected_build"' in user_payload
    assert "回答格式至少要有" in user_payload
