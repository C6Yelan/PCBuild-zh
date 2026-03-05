# backend/tests/test_chat_p3_context_pack_render.py
from __future__ import annotations

from copy import deepcopy

from backend.services.chat.context_pack.render import (
    build_context_pack,
    canonicalize_text_for_hash,
    hash_context_pack,
)


def _sample_compressed_candidates() -> dict[str, list[dict[str, object]]]:
    return {
        "CPU": [
            {
                "part_id": "cpu-1",
                "category": "CPU",
                "display_name": "Ryzen 7 7700",
                "key_specs": {
                    "socket_hint": "AM5",
                    "cores_hint": 8,
                },
                "price": 8990,
                "source": "coolpc",
                "source_url": "https://example.invalid/cpu-1",
                "run_id": "run-cpu-1",
            }
        ],
        "GPU": [
            {
                "part_id": "gpu-1",
                "category": "GPU",
                "display_name": "RTX 4070",
                "key_specs": {
                    "vram_gb_hint": 12,
                    "aib_hint": "MSI",
                },
                "price": None,
                "source": "coolpc",
                "source_url": "https://example.invalid/gpu-1",
                "snapshot_id": "snapshot-gpu-1",
            }
        ],
    }


def test_build_context_pack_is_deterministic_with_scrambled_spec_order() -> None:
    left_input = _sample_compressed_candidates()
    right_input = deepcopy(left_input)
    right_input["CPU"][0]["key_specs"] = {
        "cores_hint": 8,
        "socket_hint": "AM5",
    }

    left = build_context_pack(
        compressed_by_category=left_input,
        category_order=["CPU", "GPU"],
        enable_rerank=False,
    )
    right = build_context_pack(
        compressed_by_category=right_input,
        category_order=["CPU", "GPU"],
        enable_rerank=False,
    )

    assert left.text == right.text
    assert left.hash == right.hash


def test_hash_context_pack_matches_for_crlf_and_lf() -> None:
    lf_text = "line1\nline2\n"
    crlf_text = "line1\r\nline2\r\n"

    assert canonicalize_text_for_hash(lf_text) == "line1\nline2\n"
    assert canonicalize_text_for_hash(crlf_text) == "line1\nline2\n"
    assert hash_context_pack(lf_text) == hash_context_pack(crlf_text)


def test_build_context_pack_card_contains_required_fields() -> None:
    pack = build_context_pack(
        compressed_by_category=_sample_compressed_candidates(),
        category_order=["CPU", "GPU"],
        enable_rerank=False,
    )

    assert "[CPU#cpu-1]" in pack.text
    assert "source=coolpc" in pack.text
    assert "url=https://example.invalid/cpu-1" in pack.text
    assert "snapshot=run-cpu-1" in pack.text
    assert "snapshot=snapshot-gpu-1" in pack.text


def test_build_context_pack_keeps_empty_category_section() -> None:
    pack = build_context_pack(
        compressed_by_category={"CPU": []},
        category_order=["CPU"],
        enable_rerank=False,
    )

    assert "=== CPU CANDIDATES ===" in pack.text
    assert "(no candidates)" in pack.text


def test_build_context_pack_rerank_prefers_budget_distance_when_available() -> None:
    compressed = {
        "CPU": [
            {
                "part_id": "cpu-a",
                "category": "CPU",
                "display_name": "A model",
                "key_specs": {},
                "price": 3000,
                "source": "coolpc",
                "source_url": "https://example.invalid/cpu-a",
                "run_id": "run-a",
            },
            {
                "part_id": "cpu-z",
                "category": "CPU",
                "display_name": "Z model",
                "key_specs": {},
                "price": 5900,
                "source": "coolpc",
                "source_url": "https://example.invalid/cpu-z",
                "run_id": "run-z",
            },
        ]
    }

    pack = build_context_pack(
        compressed_by_category=compressed,
        category_order=["CPU"],
        enable_rerank=True,
        demand={"min_price": 5000, "max_price": 7000},
    )

    lines = [line for line in pack.text.splitlines() if line.startswith("[CPU#")]
    assert lines[0].startswith("[CPU#cpu-z]")
    assert lines[1].startswith("[CPU#cpu-a]")
