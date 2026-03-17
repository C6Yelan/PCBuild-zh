from __future__ import annotations

import re

from ..shared_specs import extract_limit_hint
from ..shared_specs import extract_warranty_years
from .expansion_card_bus_specs import (
    USB4_RE,
    extract_expansion_card_host_bus,
    extract_expansion_card_kind,
    extract_expansion_card_m2_slot_count,
    extract_expansion_card_nvme_only,
    extract_expansion_card_pcie_gen,
    extract_expansion_card_pcie_lanes,
)
from .expansion_card_port_specs import (
    DISPLAYPORT_RE,
    MINI_DP_RE,
    PARALLEL_RE,
    SATA_RE,
    SERIAL_RE,
    THUNDERBOLT_RE,
    TYPEA_RE,
    TYPEC_RE,
    extract_expansion_card_bandwidth,
    extract_expansion_card_chipset,
    extract_expansion_card_header,
    extract_expansion_card_keyword_count,
    extract_expansion_card_low_profile_bracket,
    extract_expansion_card_platform_support,
)

_LIMIT_RE = re.compile(r"(限組裝|限購|限量|客訂)")
_BUNDLE_RE = re.compile(r"(大全配|套裝|組合|bundle)", flags=re.IGNORECASE)
_ACCESSORY_RE = re.compile(r"轉接線|延長線|線材|轉接頭|配件", flags=re.IGNORECASE)
_CARD_RE = re.compile(r"CARD|轉接卡|擴充卡", flags=re.IGNORECASE)


def extract_expansion_card_spec_hints(
    *,
    line: str,
    desc: list[str],
    texts: list[str],
) -> dict[str, object]:
    card_kind_hint = extract_expansion_card_kind(texts)
    host_bus_hint = extract_expansion_card_host_bus(texts)
    pcie_gen_hint = extract_expansion_card_pcie_gen(texts, host_bus_hint)
    pcie_lanes_hint = extract_expansion_card_pcie_lanes(texts)
    m2_slot_count_hint = extract_expansion_card_m2_slot_count(texts)
    nvme_only_hint = extract_expansion_card_nvme_only(texts)
    has_accessory_term = any(_ACCESSORY_RE.search(text or "") for text in texts)
    has_card_term = host_bus_hint is not None or any(_CARD_RE.search(text or "") for text in texts)

    return {
        "card_kind_hint": card_kind_hint,
        "host_bus_hint": host_bus_hint,
        "pcie_gen_hint": pcie_gen_hint,
        "pcie_lanes_hint": pcie_lanes_hint,
        "m2_slot_count_hint": m2_slot_count_hint,
        "nvme_only_hint": nvme_only_hint,
        "usb4_port_count_hint": extract_expansion_card_keyword_count(texts, USB4_RE, before_keyword=r"USB\s*4"),
        "thunderbolt_port_count_hint": extract_expansion_card_keyword_count(texts, THUNDERBOLT_RE, before_keyword=r"Thunderbolt|TB[45]"),
        "usb_typec_port_count_hint": extract_expansion_card_keyword_count(texts, TYPEC_RE, before_keyword=r"Type-?C|TYPEC"),
        "usb_typea_port_count_hint": extract_expansion_card_keyword_count(texts, TYPEA_RE, before_keyword=r"Type-?A|TYPEA"),
        "sata_port_count_hint": extract_expansion_card_keyword_count(texts, SATA_RE, before_keyword=r"SATA"),
        "rs232_port_count_hint": extract_expansion_card_keyword_count(texts, SERIAL_RE, before_keyword=r"RS232|Serial"),
        "parallel_port_count_hint": extract_expansion_card_keyword_count(texts, PARALLEL_RE, before_keyword=r"Parallel|LPT"),
        "displayport_in_count_hint": extract_expansion_card_keyword_count(texts, DISPLAYPORT_RE, before_keyword=r"DisplayPort"),
        "mini_dp_in_count_hint": extract_expansion_card_keyword_count(texts, MINI_DP_RE, before_keyword=r"Mini\s*DP"),
        "bandwidth_gbps_hint": extract_expansion_card_bandwidth(texts),
        "chipset_hint": extract_expansion_card_chipset(texts),
        "internal_header_hint": extract_expansion_card_header(texts),
        "low_profile_bracket_included_hint": extract_expansion_card_low_profile_bracket(texts),
        "platform_support_hint": extract_expansion_card_platform_support(desc),
        "warranty_years": extract_warranty_years(texts),
        "limit_hint": extract_limit_hint(texts, _LIMIT_RE),
        "is_bundle": True if any(_BUNDLE_RE.search(text or "") for text in texts) else None,
        "is_accessory": True if (has_accessory_term and not has_card_term) else None,
    }
