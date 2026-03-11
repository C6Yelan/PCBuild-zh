# backend/tests/chat/context_pack/test_retrieval_contracts.py
import pytest
from pydantic import ValidationError

from backend.services.chat.context_pack import CandidatePart, P1RetrievalResult


def test_candidate_part_contract_fields() -> None:
    candidate = CandidatePart(
        part_id="00000000-0000-0000-0000-000000000001",
        category="CPU",
        display_name="Ryzen 7 7700",
        key_specs={"socket": "AM5"},
        price=8990,
        source="coolpc",
        source_url="https://example.invalid/item/1",
        run_id="11111111-1111-1111-1111-111111111111",
    )

    result = P1RetrievalResult(items_by_category={"CPU": [candidate]})
    dumped = result.model_dump()
    assert dumped["items_by_category"]["CPU"][0]["part_id"] == candidate.part_id
    assert dumped["items_by_category"]["CPU"][0]["key_specs"]["socket"] == "AM5"


def test_candidate_part_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        CandidatePart(
            part_id="00000000-0000-0000-0000-000000000001",
            category="CPU",
            display_name="Ryzen 7 7700",
            key_specs={},
            price=None,
            source="coolpc",
            source_url="https://example.invalid/item/1",
            run_id="11111111-1111-1111-1111-111111111111",
            extra_field="blocked",
        )
