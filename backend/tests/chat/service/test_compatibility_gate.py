from __future__ import annotations

from backend.services.chat.build_policy import BuildRequestProfile, apply_build_candidate_gate
from backend.services.chat.context_pack.retrieval import CandidatePart, P1RetrievalResult


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


def test_apply_build_candidate_gate_drops_underpowered_psu() -> None:
    retrieval_result = P1RetrievalResult(
        items_by_category={
            "CPU": [
                _candidate(
                    part_id="cpu-9700x",
                    category="CPU",
                    display_name="Ryzen 7 9700X",
                    key_specs={"socket_hint": "AM5", "tdp_hint": 120},
                )
            ],
            "GPU": [
                _candidate(
                    part_id="gpu-5070",
                    category="GPU",
                    display_name="RTX 5070 Gaming OC",
                    key_specs={"power_w_hint": 250},
                )
            ],
            "PSU": [
                _candidate(
                    part_id="psu-450",
                    category="PSU",
                    display_name="450W Bronze",
                    key_specs={"wattage_w_hint": 450},
                ),
                _candidate(
                    part_id="psu-750",
                    category="PSU",
                    display_name="750W Gold",
                    key_specs={"wattage_w_hint": 750},
                ),
            ],
        }
    )

    result = apply_build_candidate_gate(
        retrieval_result,
        profile=BuildRequestProfile(enabled=True, request_mode="build"),
    )

    assert [item.part_id for item in result.retrieval_result.items_by_category["PSU"]] == ["psu-750"]
    assert any(
        event["category"] == "PSU" and event["reason"] == "psu_capacity"
        for event in result.events
    )
