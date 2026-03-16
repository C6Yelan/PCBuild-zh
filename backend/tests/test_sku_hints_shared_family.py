from __future__ import annotations

from backend.services.crawler.parsers.sku_hints.case import extract_case_hints
from backend.services.crawler.parsers.sku_hints.case_fan import (
    extract_case_fan_listing_hints,
)
from backend.services.crawler.parsers.sku_hints.cooler import extract_cooler_hints
from backend.services.crawler.parsers.sku_hints.expansion_card import (
    extract_expansion_card_hints,
)
from backend.services.crawler.parsers.sku_hints.liquid_cooling import (
    extract_liquid_cooling_hints,
)
from backend.services.crawler.parsers.sku_hints.mb import extract_mb_hints
from backend.services.crawler.parsers.sku_hints.psu import (
    extract_psu_hints,
    extract_psu_sku_hint,
)
from backend.services.crawler.parsers.sku_hints.ram import extract_ram_hints
from backend.services.crawler.parsers.sku_hints.ssd import extract_ssd_hints
from backend.services.crawler.parsers.sku_hints.hdd import extract_hdd_hints


def test_cooler_hints_keep_brand_model_height_and_warranty() -> None:
    sku_hint, extra = extract_cooler_hints("利民 PA120 散熱器 / 高15.5cm / PWM / ARGB / 五年保")

    assert sku_hint == "利民 PA120"
    assert extra["brand_hint"] == "THERMALRIGHT"
    assert extra["model_hint"] == "利民 PA120"
    assert extra["height_mm_hint"] == 155
    assert extra["pwm_hint"] is True
    assert extra["rgb_hint"] is True
    assert extra["warranty_years"] == 5


def test_liquid_cooling_hints_keep_registration_warranty_and_thickness() -> None:
    sku_hint, extra = extract_liquid_cooling_hints(
        "聯力 Galahad II LCD 360 / 厚:5.5cm / ARGB / 註冊 3+3 年"
    )

    assert sku_hint == "聯力 Galahad II LCD 360"
    assert extra["brand_hint"] == "LIANLI"
    assert extra["model_hint"] == "聯力 Galahad II LCD 360"
    assert extra["radiator_size_mm_hint"] == 360
    assert extra["radiator_thickness_mm_hint"] == 55
    assert extra["rgb_hint"] == "argb"
    assert extra["warranty_years"] == 6


def test_case_hints_keep_labeled_length_parsing() -> None:
    sku_hint, extra = extract_case_hints(
        "華碩 Prime AP201 / 顯卡長36.1 / CPU高17",
        ["水冷支援 240 360", "前I/O：USB-C"],
    )

    assert sku_hint == "華碩 Prime AP201"
    assert extra["brand_hint"] == "華碩"
    assert extra["model_hint"] == "華碩 Prime AP201"
    assert extra["gpu_max_length_mm_hint"] == 361
    assert extra["cpu_cooler_max_height_mm_hint"] == 170
    assert extra["radiator_support_mm_hint"] == [240, 360]


def test_expansion_card_hints_keep_brand_and_port_counts() -> None:
    sku_hint, extra = extract_expansion_card_hints(
        "華碩 USB4 擴充卡 / USB4*2 / Type-C*2",
        None,
    )

    assert sku_hint == "華碩 USB4 擴充卡"
    assert extra["brand_hint"] == "華碩"
    assert extra["card_kind_hint"] == "usb4"
    assert extra["usb4_port_count_hint"] == 2
    assert extra["usb_typec_port_count_hint"] == 2


def test_psu_sku_hint_keeps_brand_alias_cleanup() -> None:
    assert extract_psu_sku_hint("華碩(ASUS) TUF-750G ATX3.1 金牌") == "華碩 TUF-750G"


def test_psu_hints_keep_native_connector_and_warranty() -> None:
    sku_hint, extra = extract_psu_hints(
        "華碩(ASUS) TUF-750G ATX3.1 金牌",
        ["原生 12V-2x6 x1", "10年保", "智慧停轉"],
    )

    assert sku_hint == "華碩 TUF-750G"
    assert extra["efficiency_hint"] == "gold"
    assert extra["atx_version_hint"] == "3.1"
    assert extra["native_12v_connector_hint"] == "12v-2x6"
    assert extra["native_12v_connector_count_hint"] == 1
    assert extra["warranty_years"] == 10


def test_mb_hints_keep_socket_chipset_and_variant() -> None:
    sku_hint, extra = extract_mb_hints("華碩 ROG STRIX B850-A GAMING WIFI BTF ATX")

    assert sku_hint == "B850-A GAMING WIFI BTF"
    assert extra["brand_hint"] == "ASUS"
    assert extra["chipset_hint"] == "B850"
    assert extra["socket_hint"] == "AM5"
    assert extra["form_factor_hint"] == "ATX"


def test_case_fan_hints_keep_pack_pwm_and_controller_details() -> None:
    sku_hint, extra = extract_case_fan_listing_hints(
        "聯力 UNI FAN SL-INF 120 RGB 三風扇組 / PWM / 120mm / 4-Pin / 5V 3-Pin / 含控制器 / 三年保",
        None,
    )

    assert sku_hint == "聯力 UNI FAN SL-INF 120 RGB 三風扇組"
    assert extra["fan_size_mm_hint"] == 120
    assert extra["pack_count_hint"] == 3
    assert extra["pwm_hint"] is True
    assert extra["fan_connector_hint"] is None
    assert extra["rgb_header_hint"] == "5v_3pin"
    assert extra["controller_included_hint"] is True
    assert extra["warranty_years"] == 3
    assert extra["is_accessory"] is None


def test_ssd_hints_keep_capacity_protocol_and_warranty() -> None:
    sku_hint, extra = extract_ssd_hints("Crucial T500 1TB M.2 PCIe Gen4 NVMe 讀7300/6800 五年保")

    assert sku_hint == "Crucial T500 1TB M.2 PCIe Gen4 NVMe 讀7300/6800 五年保"
    assert extra["brand_hint"] == "CRUCIAL"
    assert extra["capacity_gib"] == 931
    assert extra["form_factor_hint"] == "M.2"
    assert extra["interface_hint"] == "PCIe"
    assert extra["pcie_gen_hint"] == 4
    assert extra["protocol_hint"] == "NVMe"
    assert extra["seq_read_mb_s"] == 7300
    assert extra["seq_write_mb_s"] == 6800
    assert extra["warranty_years"] == 5


def test_ram_hints_keep_kit_capacity_and_rgb_expo() -> None:
    sku_hint, extra = extract_ram_hints("金士頓 Fury Beast DDR5-6000 16G*2 CL30 RGB EXPO")

    assert sku_hint == "金士頓 Fury Beast DDR 5-6000 16 G*2 CL 30 RGB EXPO"
    assert extra["maker_hint"] == "KINGSTON"
    assert extra["ddr_gen_hint"] == "DDR5"
    assert extra["speed_mts_hint"] == 6000
    assert extra["capacity_gb_hint"] == 32
    assert extra["kit_dimms_hint"] == 2
    assert extra["per_dimm_gb_hint"] == 16
    assert extra["cl_hint"] == 30
    assert extra["expo_hint"] is True
    assert extra["rgb_hint"] is True


def test_hdd_hints_keep_series_segment_and_capacity() -> None:
    sku_hint, extra = extract_hdd_hints("Seagate【那嘶狼】IronWolf 8TB 3.5吋 NAS 7200轉/256MB/三年保")

    assert sku_hint == "Seagate"
    assert extra["brand_hint"] == "SEAGATE"
    assert extra["model_hint"] == "Seagate"
    assert extra["capacity_gib"] == 7451
    assert extra["form_factor_hint"] == '3.5"'
    assert extra["interface_hint"] == "SATA"
    assert extra["rpm_hint"] == 7200
    assert extra["cache_mb_hint"] == 256
    assert extra["series_hint"] == "那嘶狼"
    assert extra["segment_hint"] == "NAS"
