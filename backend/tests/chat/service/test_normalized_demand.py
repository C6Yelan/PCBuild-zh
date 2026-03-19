from __future__ import annotations

from backend.services.chat.contracts import NormalizedDemand


def test_normalized_demand_coerces_categories_and_literals() -> None:
    demand = NormalizedDemand.model_validate(
        {
            "request_mode": "singlepart",
            "categories": ["處理器", "gpu", "主機板", "GPU"],
            "usage_profile": "Gaming",
            "preferred_cpu_vendor": "amd",
            "preferred_gpu_vendor": "nvidia",
            "size_preference": "mini-itx",
            "normalization_source": "ai_structured",
        }
    )

    assert demand.request_mode == "single_part"
    assert demand.categories == ["CPU", "GPU", "MB"]
    assert demand.usage_profile == "gaming"
    assert demand.preferred_cpu_vendor == "AMD"
    assert demand.preferred_gpu_vendor == "NVIDIA"
    assert demand.size_preference == "ITX"


def test_normalized_demand_derives_budget_target_from_budget_max() -> None:
    demand = NormalizedDemand.model_validate(
        {
            "request_mode": "build",
            "categories": ["CPU", "MB", "RAM"],
            "budget_max": 40000,
            "normalization_source": "rule_fallback",
        }
    )

    assert demand.budget_max == 40000
    assert demand.budget_target == 38000
    assert demand.allow_bundle is False
    assert demand.allow_board_bundle is False
    assert demand.allow_workstation_gpu is False
