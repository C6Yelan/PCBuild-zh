# backend/tests/test_chat_p2_compress_candidates.py
from __future__ import annotations

from copy import deepcopy

from backend.services.chat.context_pack.compress import compress_candidates


def test_compress_candidates_keeps_fixed_fields_and_whitelisted_specs() -> None:
    p1_result = {
        "items_by_category": {
            "CPU": [
                {
                    "part_id": "cpu-1",
                    "category": "CPU",
                    "display_name": "Ryzen 7 7700",
                    "key_specs": {
                        "socket": " AM5 ",
                        "cores": 8,
                        "tdp": "65W",
                    },
                    "price": 8990,
                    "source": "coolpc",
                    "source_url": "https://example.invalid/cpu-1",
                    "run_id": "run-1",
                    "inventory": 7,
                }
            ]
        }
    }

    compressed, drop_log = compress_candidates(
        p1_result,
        spec_whitelist_by_category={"CPU": ["socket", "cores"]},
        max_value_len=120,
        max_specs_per_part=12,
    )

    item = compressed["CPU"][0]
    assert item == {
        "part_id": "cpu-1",
        "category": "CPU",
        "display_name": "Ryzen 7 7700",
        "key_specs": {"cores": "8", "socket": "AM5"},
        "price": 8990,
        "source": "coolpc",
        "source_url": "https://example.invalid/cpu-1",
        "run_id": "run-1",
    }

    drop = drop_log["cpu-1"]
    assert drop["dropped_fields"] == ["inventory"]
    assert drop["dropped_specs"] == ["tdp"]
    assert drop["truncated_specs"] == {}
    assert "not_whitelisted" in drop["reason"]


def test_compress_candidates_truncates_long_spec_value() -> None:
    p1_result = {
        "items_by_category": {
            "GPU": [
                {
                    "part_id": "gpu-1",
                    "category": "GPU",
                    "display_name": "Test GPU",
                    "key_specs": {
                        "name": "  ABC   DEF   GHI  ",
                    },
                    "price": 10000,
                    "source": "coolpc",
                    "source_url": "https://example.invalid/gpu-1",
                    "run_id": "run-2",
                }
            ]
        }
    }

    compressed, drop_log = compress_candidates(
        p1_result,
        spec_whitelist_by_category={"GPU": ["name"]},
        max_value_len=7,
        max_specs_per_part=12,
    )

    assert compressed["GPU"][0]["key_specs"]["name"] == "ABC DEF"
    assert drop_log["gpu-1"]["truncated_specs"]["name"] == {"orig_len": 11, "new_len": 7}
    assert "value_too_long" in drop_log["gpu-1"]["reason"]


def test_compress_candidates_trims_specs_by_sorted_keys_when_too_many() -> None:
    p1_result = {
        "items_by_category": {
            "RAM": [
                {
                    "part_id": "ram-1",
                    "category": "RAM",
                    "display_name": "Test RAM",
                    "key_specs": {
                        "z_key": "z",
                        "a_key": "a",
                        "m_key": "m",
                    },
                    "price": 2500,
                    "source": "coolpc",
                    "source_url": "https://example.invalid/ram-1",
                    "run_id": "run-3",
                }
            ]
        }
    }

    compressed, drop_log = compress_candidates(
        p1_result,
        spec_whitelist_by_category={},
        max_value_len=120,
        max_specs_per_part=2,
    )

    assert list(compressed["RAM"][0]["key_specs"].keys()) == ["a_key", "m_key"]
    assert drop_log["ram-1"]["dropped_specs"] == ["z_key"]
    assert "too_many_specs" in drop_log["ram-1"]["reason"]
    assert "fallback_used" in drop_log["ram-1"]["reason"]


def test_compress_candidates_is_deterministic() -> None:
    p1_result = {
        "items_by_category": {
            "CPU": [
                {
                    "part_id": "cpu-2",
                    "category": "CPU",
                    "display_name": "CPU X",
                    "key_specs": {"b": "2", "a": "1"},
                    "price": 5000,
                    "source": "coolpc",
                    "source_url": "https://example.invalid/cpu-2",
                    "run_id": "run-4",
                }
            ]
        }
    }

    left = compress_candidates(
        deepcopy(p1_result),
        spec_whitelist_by_category={"CPU": ["a", "b"]},
        max_value_len=120,
        max_specs_per_part=12,
    )
    right = compress_candidates(
        deepcopy(p1_result),
        spec_whitelist_by_category={"CPU": ["a", "b"]},
        max_value_len=120,
        max_specs_per_part=12,
    )
    assert left == right


def test_compress_candidates_keeps_traceability_fields() -> None:
    p1_result = {
        "items_by_category": {
            "MB": [
                {
                    "part_id": "mb-1",
                    "category": "MB",
                    "display_name": "Test MB",
                    "key_specs": {"socket": "AM5"},
                    "price": 4500,
                    "source": "coolpc",
                    "source_url": "https://example.invalid/mb-1",
                    "snapshot_id": "snap-1",
                }
            ]
        }
    }

    compressed, _ = compress_candidates(
        p1_result,
        spec_whitelist_by_category={"MB": ["socket"]},
        max_value_len=120,
        max_specs_per_part=12,
    )

    item = compressed["MB"][0]
    assert item["source_url"] == "https://example.invalid/mb-1"
    assert item["snapshot_id"] == "snap-1"
