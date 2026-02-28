# backend/tests/test_chat_p2_compress.py
from backend.services.chat.context_pack import compress_candidates


def _find_drop_log(drop_log, *, part_id: str):
    for item in drop_log:
        if item.part_id == part_id:
            return item
    raise AssertionError(f"drop_log not found for part_id={part_id}")


def test_whitelist_and_drop_log_for_cpu_mb_gpu() -> None:
    candidates = {
        "CPU": [
            {
                "part_id": "cpu-1",
                "category": "CPU",
                "display_name": "CPU A",
                "key_specs": {
                    "socket": "AM5",
                    "cores": 8,
                    "threads": 16,
                    "marketing_title": "Fast and cool",
                },
                "price": 9999,
                "source": "coolpc",
                "source_url": "https://example.com/cpu-1",
                "snapshot_id": "snap-1",
                "run_id": "run-1",
            }
        ],
        "MB": [
            {
                "part_id": "mb-1",
                "category": "MB",
                "display_name": "MB A",
                "key_specs": {
                    "socket": "AM5",
                    "chipset": "B650",
                    "ddr_gen": "DDR5",
                    "promo": "limited-time",
                },
                "price": 5999,
                "source": "coolpc",
                "source_url": "https://example.com/mb-1",
                "snapshot_id": "snap-2",
                "run_id": "run-2",
            }
        ],
        "GPU": [
            {
                "part_id": "gpu-1",
                "category": "GPU",
                "display_name": "GPU A",
                "key_specs": {
                    "chipset": "RTX 5070",
                    "vram_gb": 12,
                    "watt": 250,
                    "campaign": "new arrival",
                },
                "price": 18999,
                "source": "coolpc",
                "source_url": "https://example.com/gpu-1",
                "snapshot_id": "snap-3",
                "run_id": "run-3",
            }
        ],
    }

    compressed_by_category, drop_log = compress_candidates(candidates)

    cpu_specs = compressed_by_category["CPU"][0].key_specs
    assert set(cpu_specs.keys()) == {"socket", "cores", "threads"}

    mb_specs = compressed_by_category["MB"][0].key_specs
    assert set(mb_specs.keys()) == {"socket", "chipset", "ram_type"}
    assert mb_specs["ram_type"] == "DDR5"

    gpu_specs = compressed_by_category["GPU"][0].key_specs
    assert set(gpu_specs.keys()) == {"chipset", "vram_gb", "power_w"}
    assert gpu_specs["power_w"] == 250

    cpu_drop = _find_drop_log(drop_log, part_id="cpu-1")
    assert "marketing_title" in cpu_drop.dropped_keys
    assert cpu_drop.reasons and cpu_drop.reasons["marketing_title"] == "not_whitelisted"

    mb_drop = _find_drop_log(drop_log, part_id="mb-1")
    assert "promo" in mb_drop.dropped_keys
    assert mb_drop.reasons and mb_drop.reasons["promo"] == "not_whitelisted"

    gpu_drop = _find_drop_log(drop_log, part_id="gpu-1")
    assert "campaign" in gpu_drop.dropped_keys
    assert gpu_drop.reasons and gpu_drop.reasons["campaign"] == "not_whitelisted"


def test_unknown_category_uses_fallback_whitelist() -> None:
    candidates = {
        "SOUND_CARD": [
            {
                "part_id": "sc-1",
                "category": "SOUND_CARD",
                "display_name": "Card A",
                "key_specs": {
                    "interface": "PCIe x1",
                    "chipset": "AXX",
                    "channels": "7.1",
                },
                "source": "coolpc",
                "source_url": "https://example.com/sc-1",
            }
        ]
    }

    compressed_by_category, drop_log = compress_candidates(candidates)
    specs = compressed_by_category["SOUND_CARD"][0].key_specs

    assert set(specs.keys()) == {"interface", "chipset"}

    drop_item = _find_drop_log(drop_log, part_id="sc-1")
    assert "channels" in drop_item.dropped_keys
    assert drop_item.reasons and drop_item.reasons["channels"] == "not_whitelisted"


def test_too_long_string_is_truncated_and_logged() -> None:
    very_long = "A" * 240
    candidates = {
        "GPU": [
            {
                "part_id": "gpu-2",
                "category": "GPU",
                "display_name": "GPU B",
                "key_specs": {
                    "outputs": very_long,
                    "chipset": "RTX 5080",
                },
                "source": "coolpc",
                "source_url": "https://example.com/gpu-2",
            }
        ]
    }

    compressed_by_category, drop_log = compress_candidates(candidates)
    specs = compressed_by_category["GPU"][0].key_specs

    assert len(specs["outputs"]) == 200
    drop_item = _find_drop_log(drop_log, part_id="gpu-2")
    assert drop_item.reasons and drop_item.reasons["outputs"] == "too_long"


def test_empty_values_are_removed() -> None:
    candidates = {
        "MB": [
            {
                "part_id": "mb-2",
                "category": "MB",
                "display_name": "MB B",
                "key_specs": {
                    "socket": "LGA1700",
                    "chipset": None,
                    "wifi": "N/A",
                    "ram_slots": "",
                    "pcie_version": "5.0",
                },
                "source": "coolpc",
                "source_url": "https://example.com/mb-2",
            }
        ]
    }

    compressed_by_category, drop_log = compress_candidates(candidates)
    specs = compressed_by_category["MB"][0].key_specs

    assert specs == {"pcie_version": "5.0", "socket": "LGA1700"}

    drop_item = _find_drop_log(drop_log, part_id="mb-2")
    assert set(drop_item.dropped_keys) >= {"chipset", "wifi", "ram_slots"}
    assert drop_item.reasons and drop_item.reasons["chipset"] == "empty"
    assert drop_item.reasons["wifi"] == "empty"
    assert drop_item.reasons["ram_slots"] == "empty"
