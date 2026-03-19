from __future__ import annotations

from backend.services.chat.build_policy import (
    BuildRequestProfile,
    apply_build_candidate_gate,
    build_request_profile,
    classify_candidate,
)
from backend.services.chat.context_pack.retrieval import CandidatePart, P1Demand, P1RetrievalResult


def _candidate(
    *,
    part_id: str,
    category: str,
    display_name: str,
    key_specs: dict[str, object],
    price: int | None = None,
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


def test_build_request_profile_marks_full_build_and_budget_targets() -> None:
    profile = build_request_profile(
        message_text="幫我配一台 4 萬內遊戲機",
        categories=["CPU", "MB", "RAM", "SSD", "PSU", "CASE", "GPU"],
        retrieval_demand=P1Demand(budget=40000),
    )

    assert profile.enabled is True
    assert profile.target_total_price == 38000
    assert profile.minimum_budget_utilization == 36000


def test_classify_candidate_detects_bundle_workstation_and_ram_unit() -> None:
    gpu = _candidate(
        part_id="gpu-pro",
        category="GPU",
        display_name="NVIDIA RTX A4000 Professional",
        key_specs={},
    )
    ram = _candidate(
        part_id="ram-kit",
        category="RAM",
        display_name="DDR5 16GBx2 Kit",
        key_specs={"kit_dimms_hint": 2},
    )
    cpu_bundle = _candidate(
        part_id="cpu-bundle",
        category="CPU",
        display_name="Ryzen 7 9700X 主機板套餐",
        key_specs={"is_bundle": True},
    )

    assert classify_candidate(gpu).market_segment == "workstation"
    assert classify_candidate(ram).ram_sale_unit == "kit"
    cpu_semantics = classify_candidate(cpu_bundle)
    assert cpu_semantics.offer_type == "bundle"
    assert cpu_semantics.pricing_mode == "unknown"


def test_apply_build_candidate_gate_filters_semantic_noise_and_hard_incompatibility() -> None:
    retrieval_result = P1RetrievalResult(
        items_by_category={
            "CPU": [
                _candidate(
                    part_id="cpu-am4",
                    category="CPU",
                    display_name="Ryzen 5 5600",
                    key_specs={"socket_hint": "AM4"},
                ),
                _candidate(
                    part_id="cpu-am5",
                    category="CPU",
                    display_name="Ryzen 7 9700X",
                    key_specs={"socket_hint": "AM5"},
                ),
            ],
            "MB": [
                _candidate(
                    part_id="mb-am5",
                    category="MB",
                    display_name="B650 ATX",
                    key_specs={
                        "socket_hint": "AM5",
                        "memory_type_hint": "DDR5",
                        "form_factor_hint": "ATX",
                    },
                ),
                _candidate(
                    part_id="mb-bundle",
                    category="MB",
                    display_name="B650 板U Combo",
                    key_specs={
                        "socket_hint": "AM5",
                        "memory_type_hint": "DDR5",
                        "form_factor_hint": "ATX",
                        "is_bundle": True,
                    },
                ),
            ],
            "RAM": [
                _candidate(
                    part_id="ram-single",
                    category="RAM",
                    display_name="DDR5 16GB 單條",
                    key_specs={"ddr_gen_hint": "DDR5", "kit_dimms_hint": 1},
                ),
                _candidate(
                    part_id="ram-kit",
                    category="RAM",
                    display_name="DDR5 16GBx2 Kit",
                    key_specs={"ddr_gen_hint": "DDR5", "kit_dimms_hint": 2},
                ),
            ],
            "GPU": [
                _candidate(
                    part_id="gpu-workstation",
                    category="GPU",
                    display_name="RTX A4000 Professional",
                    key_specs={"length_mm_hint": 267},
                ),
                _candidate(
                    part_id="gpu-gaming",
                    category="GPU",
                    display_name="RTX 5070 Gaming OC",
                    key_specs={"length_mm_hint": 338},
                ),
            ],
            "CASE": [
                _candidate(
                    part_id="case-small",
                    category="CASE",
                    display_name="Compact ITX Case",
                    key_specs={
                        "mb_form_factor_support_hint": "Mini-ITX",
                        "gpu_max_length_mm_hint": 300,
                    },
                ),
                _candidate(
                    part_id="case-mid",
                    category="CASE",
                    display_name="Mid Tower",
                    key_specs={
                        "mb_form_factor_support_hint": "ATX / Micro-ATX / Mini-ITX",
                        "gpu_max_length_mm_hint": 360,
                    },
                ),
            ],
        }
    )

    result = apply_build_candidate_gate(
        retrieval_result,
        profile=BuildRequestProfile(enabled=True),
    )

    assert [item.part_id for item in result.retrieval_result.items_by_category["CPU"]] == ["cpu-am5"]
    assert [item.part_id for item in result.retrieval_result.items_by_category["MB"]] == ["mb-am5"]
    assert [item.part_id for item in result.retrieval_result.items_by_category["RAM"]] == ["ram-kit"]
    assert [item.part_id for item in result.retrieval_result.items_by_category["GPU"]] == ["gpu-gaming"]
    assert [item.part_id for item in result.retrieval_result.items_by_category["CASE"]] == ["case-mid"]
    assert any(
        event["stage"] == "semantic_filter" and event["category"] == "GPU" and event["reason"] == "market_segment"
        for event in result.events
    )
    assert any(
        event["stage"] == "compatibility_gate" and event["category"] == "CPU" and event["reason"] == "cpu_mb"
        for event in result.events
    )
    assert any(
        event["stage"] == "compatibility_gate" and event["category"] == "CASE"
        for event in result.events
    )


def test_apply_build_candidate_gate_relaxes_ram_single_dimm_when_no_kit_exists() -> None:
    retrieval_result = P1RetrievalResult(
        items_by_category={
            "RAM": [
                _candidate(
                    part_id="ram-single",
                    category="RAM",
                    display_name="DDR5 32GB 單條",
                    key_specs={"ddr_gen_hint": "DDR5", "kit_dimms_hint": 1},
                )
            ]
        }
    )

    result = apply_build_candidate_gate(
        retrieval_result,
        profile=BuildRequestProfile(enabled=True),
    )

    assert [item.part_id for item in result.retrieval_result.items_by_category["RAM"]] == ["ram-single"]
    assert any(
        event["stage"] == "semantic_filter"
        and event["category"] == "RAM"
        and event["reason"] == "ram_sale_unit"
        and event["action"] == "relaxed"
        for event in result.events
    )


def test_apply_build_candidate_gate_drops_case_when_gpu_exceeds_length_limit() -> None:
    retrieval_result = P1RetrievalResult(
        items_by_category={
            "GPU": [
                _candidate(
                    part_id="gpu-long",
                    category="GPU",
                    display_name="RTX 5070 Gaming OC",
                    key_specs={"length_mm_hint": 338},
                )
            ],
            "CASE": [
                _candidate(
                    part_id="case-short",
                    category="CASE",
                    display_name="Mid Tower",
                    key_specs={"gpu_max_length_mm_hint": 330},
                ),
                _candidate(
                    part_id="case-fit",
                    category="CASE",
                    display_name="Large Mid Tower",
                    key_specs={"gpu_max_length_mm_hint": 360},
                ),
            ],
        }
    )

    result = apply_build_candidate_gate(
        retrieval_result,
        profile=BuildRequestProfile(enabled=True),
    )

    assert [item.part_id for item in result.retrieval_result.items_by_category["CASE"]] == ["case-fit"]
    assert any(
        event["stage"] == "compatibility_gate"
        and event["category"] == "CASE"
        and event["reason"] == "gpu_case"
        for event in result.events
    )
