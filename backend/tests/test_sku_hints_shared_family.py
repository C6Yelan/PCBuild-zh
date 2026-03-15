from __future__ import annotations

from backend.services.crawler.parsers.sku_hints.case import extract_case_hints
from backend.services.crawler.parsers.sku_hints.cooler import extract_cooler_hints
from backend.services.crawler.parsers.sku_hints.expansion_card import (
    extract_expansion_card_hints,
)
from backend.services.crawler.parsers.sku_hints.liquid_cooling import (
    extract_liquid_cooling_hints,
)
from backend.services.crawler.parsers.sku_hints.mb import extract_mb_hints
from backend.services.crawler.parsers.sku_hints.psu import extract_psu_sku_hint


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


def test_mb_hints_keep_socket_chipset_and_variant() -> None:
    sku_hint, extra = extract_mb_hints("華碩 ROG STRIX B850-A GAMING WIFI BTF ATX")

    assert sku_hint == "B850-A GAMING WIFI BTF"
    assert extra["brand_hint"] == "ASUS"
    assert extra["chipset_hint"] == "B850"
    assert extra["socket_hint"] == "AM5"
    assert extra["form_factor_hint"] == "ATX"
