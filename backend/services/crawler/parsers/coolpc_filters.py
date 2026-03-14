from __future__ import annotations

import re

_RAM_PROMO_TITLE_RE = re.compile(r"^\s*活動", flags=re.IGNORECASE)
_RAM_PROMO_URL_RE = re.compile(r"docs\.google\.com/forms", flags=re.IGNORECASE)
_ALLOWED_COOLER_KINDS = {
    "cpu_air",
    "ssd_heatsink",
    "thermal_pad",
    "thermal_paste",
    "notebook_cooler",
}
_DETAIL_LINE_CATEGORIES = {"CASE", "PSU", "CASE_FAN", "EXPANSION_CARD"}
_SINGLE_ITEM_URL_CATEGORIES = {"SSD", "HDD", "COOLER", "LIQUID_COOLING"}
_COMPACT_EXTRA_CATEGORIES = {
    "RAM",
    "SSD",
    "HDD",
    "COOLER",
    "LIQUID_COOLING",
    "CASE",
    "PSU",
    "CASE_FAN",
    "EXPANSION_CARD",
}


def compact_extra(extra: dict | None) -> dict | None:
    if not extra:
        return extra
    return {key: value for key, value in extra.items() if value is not None}


def normalize_listing_extra(category: str, extra: dict | None) -> dict | None:
    if category in _COMPACT_EXTRA_CATEGORIES:
        return compact_extra(extra)
    return extra


def is_ram_promo(title: str, url: str, price: int | None) -> bool:
    if price is not None and price <= 1:
        return True
    if _RAM_PROMO_TITLE_RE.search(title or ""):
        return True
    if _RAM_PROMO_URL_RE.search(url or ""):
        return True
    return False


def requires_detail_lines(category: str) -> bool:
    return category in _DETAIL_LINE_CATEGORIES


def requires_single_item_url(category: str) -> bool:
    return category in _SINGLE_ITEM_URL_CATEGORIES


def should_skip_listing(
    *,
    category: str,
    title: str,
    price: int | None,
    hints_extra: dict | None,
    hints_is_bundle: bool,
) -> bool:
    if category == "CPU" and hints_extra and hints_extra.get("is_accessory"):
        return True
    if category == "MB" and hints_is_bundle:
        return True
    if category == "GPU" and hints_extra and hints_extra.get("is_accessory"):
        return True
    if category == "LIQUID_COOLING" and hints_extra and hints_extra.get("is_accessory"):
        return True
    if category == "COOLER":
        cooler_kind = (hints_extra or {}).get("cooler_kind_hint")
        if cooler_kind not in _ALLOWED_COOLER_KINDS:
            return True
        if "【提醒】" in title or (price == 1 and "提醒" in title):
            return True
    return False
