from __future__ import annotations

from backend.services.chat.build_policy import BuildRequestProfile
from backend.services.chat.build_scoring import apply_build_scoring
from backend.services.chat.context_pack.retrieval import CandidatePart, P1RetrievalResult
from backend.services.chat.contracts import NormalizedDemand


def _candidate(
    *,
    part_id: str,
    category: str,
    display_name: str,
    price: int,
    key_specs: dict[str, object],
) -> CandidatePart:
    return CandidatePart(
        part_id=part_id,
        category=category,
        display_name=display_name,
        key_specs=key_specs,
        price=price,
        source="coolpc",
        source_url=f"https://example.invalid/{part_id}",
        run_id=f"run-{part_id}",
    )


def test_apply_build_scoring_prefers_balanced_gaming_build() -> None:
    retrieval_result = P1RetrievalResult(
        items_by_category={
            "CPU": [
                _candidate(
                    part_id="cpu-high",
                    category="CPU",
                    display_name="AMD Ryzen 7 9700X",
                    price=11800,
                    key_specs={"socket_hint": "AM5"},
                ),
                _candidate(
                    part_id="cpu-mid",
                    category="CPU",
                    display_name="AMD Ryzen 5 9600X",
                    price=7600,
                    key_specs={"socket_hint": "AM5"},
                ),
            ],
            "GPU": [
                _candidate(
                    part_id="gpu-low",
                    category="GPU",
                    display_name="NVIDIA RTX 4060",
                    price=10990,
                    key_specs={"power_w_hint": 115},
                ),
                _candidate(
                    part_id="gpu-mid",
                    category="GPU",
                    display_name="NVIDIA RTX 5070",
                    price=17490,
                    key_specs={"power_w_hint": 250},
                ),
            ],
            "MB": [
                _candidate(
                    part_id="mb-low",
                    category="MB",
                    display_name="A620M Entry",
                    price=2590,
                    key_specs={
                        "socket_hint": "AM5",
                        "memory_type_hint": "DDR5",
                        "chipset_hint": "A620",
                        "form_factor_hint": "M-ATX",
                    },
                ),
                _candidate(
                    part_id="mb-mid",
                    category="MB",
                    display_name="B650M Gaming Plus",
                    price=4990,
                    key_specs={
                        "socket_hint": "AM5",
                        "memory_type_hint": "DDR5",
                        "chipset_hint": "B650",
                        "form_factor_hint": "M-ATX",
                    },
                ),
                _candidate(
                    part_id="mb-high",
                    category="MB",
                    display_name="X870 Elite",
                    price=9990,
                    key_specs={
                        "socket_hint": "AM5",
                        "memory_type_hint": "DDR5",
                        "chipset_hint": "X870",
                        "form_factor_hint": "ATX",
                    },
                ),
            ],
            "RAM": [
                _candidate(
                    part_id="ram-over",
                    category="RAM",
                    display_name="DDR5 64GBx2 Kit",
                    price=9990,
                    key_specs={"ddr_gen_hint": "DDR5", "capacity_gb_hint": 128, "kit_dimms_hint": 2},
                ),
                _candidate(
                    part_id="ram-sane",
                    category="RAM",
                    display_name="DDR5 16GBx2 Kit",
                    price=2990,
                    key_specs={"ddr_gen_hint": "DDR5", "capacity_gb_hint": 32, "kit_dimms_hint": 2},
                ),
            ],
            "SSD": [
                _candidate(
                    part_id="ssd-1tb",
                    category="SSD",
                    display_name="PCIe 4.0 1TB SSD",
                    price=2290,
                    key_specs={"capacity_gib": 1000, "pcie_gen_hint": 4},
                ),
                _candidate(
                    part_id="ssd-4tb",
                    category="SSD",
                    display_name="PCIe 4.0 4TB SSD",
                    price=7290,
                    key_specs={"capacity_gib": 4000, "pcie_gen_hint": 4},
                ),
            ],
            "PSU": [
                _candidate(
                    part_id="psu-650",
                    category="PSU",
                    display_name="650W Gold PSU",
                    price=2590,
                    key_specs={"wattage_w_hint": 650},
                ),
                _candidate(
                    part_id="psu-1000",
                    category="PSU",
                    display_name="1000W Gold PSU",
                    price=5590,
                    key_specs={"wattage_w_hint": 1000},
                ),
            ],
            "CASE": [
                _candidate(
                    part_id="case-basic",
                    category="CASE",
                    display_name="Airflow Case",
                    price=1590,
                    key_specs={"mb_form_factor_support_hint": "ATX / M-ATX", "gpu_max_length_mm_hint": 360},
                ),
                _candidate(
                    part_id="case-fancy",
                    category="CASE",
                    display_name="Premium Showcase Case",
                    price=5290,
                    key_specs={"mb_form_factor_support_hint": "ATX / M-ATX", "gpu_max_length_mm_hint": 400},
                ),
            ],
        }
    )
    profile = BuildRequestProfile(
        enabled=True,
        request_mode="build",
        usage_profile="gaming",
        budget_max=40000,
        budget_target=38000,
        target_total_price=38000,
        minimum_budget_utilization=36000,
    )
    normalized_demand = NormalizedDemand.model_validate(
        {
            "request_mode": "build",
            "usage_profile": "gaming",
            "categories": ["CPU", "GPU", "MB", "RAM", "SSD", "PSU", "CASE"],
            "budget_max": 40000,
            "preferred_cpu_vendor": "AMD",
            "preferred_gpu_vendor": "NVIDIA",
            "normalization_source": "ai_structured",
        }
    )

    result = apply_build_scoring(
        retrieval_result,
        profile=profile,
        normalized_demand=normalized_demand,
    )

    assert result.selected_candidate is not None
    selected = result.selected_candidate
    assert selected.parts_by_category["CPU"].part_id == "cpu-mid"
    assert selected.parts_by_category["GPU"].part_id == "gpu-mid"
    assert selected.parts_by_category["MB"].part_id == "mb-mid"
    assert selected.parts_by_category["RAM"].part_id == "ram-sane"
    assert selected.parts_by_category["SSD"].part_id == "ssd-1tb"
    assert selected.parts_by_category["PSU"].part_id == "psu-650"
    assert selected.parts_by_category["CASE"].part_id == "case-basic"
    assert selected.breakdown.cpu_gpu_balance_score >= 80
    assert selected.breakdown.motherboard_tier_match_score >= 80
    assert selected.breakdown.budget_utilization_score >= 80
    assert result.retrieval_result.items_by_category["MB"][0].part_id == "mb-mid"
    assert result.retrieval_result.items_by_category["RAM"][0].part_id == "ram-sane"
    assert result.context_meta is not None
    assert result.context_meta["candidate_pool_warning"] is None


def test_apply_build_scoring_marks_underutilized_candidate_pool() -> None:
    retrieval_result = P1RetrievalResult(
        items_by_category={
            "CPU": [
                _candidate(
                    part_id="cpu-mid",
                    category="CPU",
                    display_name="AMD Ryzen 5 7500F",
                    price=5200,
                    key_specs={"socket_hint": "AM5"},
                )
            ],
            "GPU": [
                _candidate(
                    part_id="gpu-mid",
                    category="GPU",
                    display_name="NVIDIA RTX 4060",
                    price=10990,
                    key_specs={"power_w_hint": 115},
                )
            ],
            "MB": [
                _candidate(
                    part_id="mb-mid",
                    category="MB",
                    display_name="B650M",
                    price=3990,
                    key_specs={"socket_hint": "AM5", "memory_type_hint": "DDR5", "chipset_hint": "B650"},
                )
            ],
            "RAM": [
                _candidate(
                    part_id="ram-sane",
                    category="RAM",
                    display_name="DDR5 16GBx2 Kit",
                    price=2590,
                    key_specs={"ddr_gen_hint": "DDR5", "capacity_gb_hint": 32, "kit_dimms_hint": 2},
                )
            ],
        }
    )
    profile = BuildRequestProfile(
        enabled=True,
        request_mode="build",
        usage_profile="gaming",
        budget_max=40000,
        budget_target=38000,
        target_total_price=38000,
        minimum_budget_utilization=36000,
    )

    result = apply_build_scoring(
        retrieval_result,
        profile=profile,
        normalized_demand=NormalizedDemand.model_validate(
            {
                "request_mode": "build",
                "usage_profile": "gaming",
                "categories": ["CPU", "GPU", "MB", "RAM"],
                "budget_max": 40000,
                "normalization_source": "ai_structured",
            }
        ),
    )

    assert result.selected_candidate is not None
    assert "candidate_pool_underutilized" in result.selected_candidate.applied_warnings
    assert result.context_meta is not None
    assert "clean 候選不足" in str(result.context_meta["candidate_pool_warning"])
