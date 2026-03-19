from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Callable, Mapping, Sequence

from backend.services.chat.contracts import NormalizedDemand
from backend.services.chat.context_pack.retrieval import CandidatePart, P1Demand, P1RetrievalResult

_BUILD_CORE_CATEGORIES = frozenset({"CPU", "MB", "RAM", "SSD", "PSU", "CASE", "GPU"})
_BUILD_INTENT_PATTERNS = (
    re.compile(r"配\s*單"),
    re.compile(r"配\s*置"),
    re.compile(r"組\s*(?:一?台)?\s*(?:電腦|主機|機)"),
    re.compile(r"整\s*機"),
    re.compile(r"文\s*書\s*機"),
    re.compile(r"遊\s*戲\s*機"),
    re.compile(r"工\s*作\s*站"),
    re.compile(r"推\s*薦.*(?:電腦|主機(?!板)|機)"),
)
_BUNDLE_PATTERNS = (
    re.compile(r"套裝"),
    re.compile(r"大全配"),
    re.compile(r"優惠組合"),
    re.compile(r"組合包"),
    re.compile(r"\bbundle\b", re.IGNORECASE),
)
_COMBO_PATTERNS = (
    re.compile(r"\bcombo\b", re.IGNORECASE),
    re.compile(r"套餐"),
    re.compile(r"搭購"),
)
_BOARD_BUNDLE_PATTERNS = (
    re.compile(r"板\s*U"),
    re.compile(r"主機板.*(?:CPU|處理器)"),
    re.compile(r"(?:CPU|處理器).*(?:主機板|MB)"),
    re.compile(r"\bmb\s*\+", re.IGNORECASE),
)
_PRICING_MODE_PATTERNS: tuple[tuple[str, tuple[re.Pattern[str], ...]], ...] = (
    (
        "搭板價",
        (
            re.compile(r"搭板價"),
            re.compile(r"主機板價"),
            re.compile(r"任搭主機板"),
            re.compile(r"板\s*U"),
        ),
    ),
    (
        "限搭",
        (
            re.compile(r"限搭"),
            re.compile(r"限組裝"),
            re.compile(r"限搭機"),
            re.compile(r"任搭"),
            re.compile(r"搭購"),
        ),
    ),
    (
        "活動價",
        (
            re.compile(r"活動價"),
            re.compile(r"促銷"),
            re.compile(r"優惠"),
            re.compile(r"特價"),
            re.compile(r"現折"),
            re.compile(r"折扣"),
        ),
    ),
)
_WORKSTATION_PATTERNS = (
    re.compile(r"workstation", re.IGNORECASE),
    re.compile(r"professional", re.IGNORECASE),
    re.compile(r"pro\s*viz", re.IGNORECASE),
    re.compile(r"quadro", re.IGNORECASE),
    re.compile(r"radeon\s+pro", re.IGNORECASE),
    re.compile(r"\brtx\s*a\d{3,4}\b", re.IGNORECASE),
    re.compile(r"\b[a-z]?wx\d{3,4}\b", re.IGNORECASE),
)
_CREATOR_PATTERNS = (
    re.compile(r"creator", re.IGNORECASE),
    re.compile(r"studio", re.IGNORECASE),
    re.compile(r"content\s*creation", re.IGNORECASE),
)
_GAMING_PATTERNS = (
    re.compile(r"gaming", re.IGNORECASE),
    re.compile(r"電競"),
    re.compile(r"遊戲"),
)
_OFFICE_PATTERNS = (
    re.compile(r"office", re.IGNORECASE),
    re.compile(r"文書"),
    re.compile(r"商用"),
)
_KIT_PATTERNS = (
    re.compile(r"\b\d+\s*[xX]\s*\d+\s*(?:GB|G)\b", re.IGNORECASE),
    re.compile(r"\d+\s*條"),
)
_SINGLE_DIMM_PATTERNS = (
    re.compile(r"單條"),
    re.compile(r"\b1\s*[xX]\s*\d+\s*(?:GB|G)\b", re.IGNORECASE),
    re.compile(r"\bone\s*dimm\b", re.IGNORECASE),
)
_FORM_FACTOR_ALIASES = {
    "EATX": "E-ATX",
    "E-ATX": "E-ATX",
    "ATX": "ATX",
    "MATX": "M-ATX",
    "MICROATX": "M-ATX",
    "MICRO-ATX": "M-ATX",
    "M-ATX": "M-ATX",
    "MITX": "MINI-ITX",
    "MINIITX": "MINI-ITX",
    "MINI-ITX": "MINI-ITX",
    "ITX": "MINI-ITX",
}
_CASE_CLASS_SUPPORT = {
    "FULL-TOWER": {"E-ATX", "ATX", "M-ATX", "MINI-ITX"},
    "MID-TOWER": {"ATX", "M-ATX", "MINI-ITX"},
    "MINI-TOWER": {"M-ATX", "MINI-ITX"},
    "SFF": {"MINI-ITX"},
}
_CPU_SOCKET_MEMORY_SUPPORT = {
    "AM4": {"DDR4"},
    "AM5": {"DDR5"},
    "STR5": {"DDR5"},
    "SWRX8": {"DDR4"},
    "LGA1200": {"DDR4"},
    "LGA1700": {"DDR4", "DDR5"},
    "LGA1851": {"DDR5"},
    "LGA4677": {"DDR5"},
}


@dataclass(frozen=True, slots=True)
class BuildRequestProfile:
    enabled: bool
    request_mode: str = "unknown"
    usage_profile: str = "unknown"
    budget_max: int | None = None
    budget_target: int | None = None
    target_total_price: int | None = None
    minimum_budget_utilization: int | None = None
    allow_bundle: bool = False
    allow_board_bundle: bool = False
    allow_workstation_gpu: bool = False


@dataclass(frozen=True, slots=True)
class SemanticClassification:
    offer_type: str
    pricing_mode: str
    market_segment: str
    ram_sale_unit: str


@dataclass(frozen=True, slots=True)
class BuildGateResult:
    retrieval_result: Any
    events: list[dict[str, str]]


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).strip().split())


def _normalize_upper_token(value: Any) -> str:
    return re.sub(r"[^A-Z0-9]+", "", _normalize_text(value).upper())


def _joined_candidate_text(candidate: CandidatePart) -> str:
    spec_parts = [
        f"{key}={_normalize_text(value)}"
        for key, value in sorted(candidate.key_specs.items())
        if value is not None and _normalize_text(value)
    ]
    return " | ".join(
        part
        for part in (
            candidate.display_name,
            candidate.category,
            " ".join(spec_parts),
        )
        if _normalize_text(part)
    )


def build_request_profile(
    *,
    normalized_demand: NormalizedDemand | None = None,
    retrieval_demand: P1Demand | None,
    message_text: str | None = None,
    categories: Sequence[str] | None = None,
) -> BuildRequestProfile:
    resolved_normalized_demand = normalized_demand
    if resolved_normalized_demand is None:
        resolved_categories = [str(category).strip() for category in (categories or []) if str(category).strip()]
        resolved_request_mode = "build" if len(set(resolved_categories) & _BUILD_CORE_CATEGORIES) >= 3 else "single_part"
        resolved_normalized_demand = NormalizedDemand(
            request_mode=resolved_request_mode,
            categories=resolved_categories,
            normalization_source="rule_fallback",
        )

    requested_categories = {
        str(category).strip()
        for category in resolved_normalized_demand.categories
        if str(category).strip()
    }
    explicit_build_categories = len(requested_categories & _BUILD_CORE_CATEGORIES) >= 3
    enabled = resolved_normalized_demand.request_mode in {"build", "upgrade"} or explicit_build_categories
    if not enabled:
        return BuildRequestProfile(enabled=False)

    budget = resolved_normalized_demand.budget_max
    if budget is None and retrieval_demand is not None:
        budget = retrieval_demand.budget
    if budget is None or budget <= 0:
        return BuildRequestProfile(
            enabled=True,
            request_mode=resolved_normalized_demand.request_mode,
            usage_profile=resolved_normalized_demand.usage_profile,
            budget_max=resolved_normalized_demand.budget_max,
            budget_target=resolved_normalized_demand.budget_target,
            allow_bundle=resolved_normalized_demand.allow_bundle,
            allow_board_bundle=resolved_normalized_demand.allow_board_bundle,
            allow_workstation_gpu=resolved_normalized_demand.allow_workstation_gpu,
        )
    return BuildRequestProfile(
        enabled=True,
        request_mode=resolved_normalized_demand.request_mode,
        usage_profile=resolved_normalized_demand.usage_profile,
        budget_max=resolved_normalized_demand.budget_max,
        budget_target=resolved_normalized_demand.budget_target,
        target_total_price=max(1, int(round(budget * 0.95))),
        minimum_budget_utilization=max(1, int(round(budget * 0.90))),
        allow_bundle=resolved_normalized_demand.allow_bundle,
        allow_board_bundle=resolved_normalized_demand.allow_board_bundle,
        allow_workstation_gpu=resolved_normalized_demand.allow_workstation_gpu,
    )


def classify_candidate(candidate: CandidatePart) -> SemanticClassification:
    full_text = _joined_candidate_text(candidate)
    key_specs = candidate.key_specs if isinstance(candidate.key_specs, Mapping) else {}

    offer_type = "single_part"
    if bool(key_specs.get("is_bundle")):
        offer_type = "bundle"
    elif any(pattern.search(full_text) for pattern in _BOARD_BUNDLE_PATTERNS):
        offer_type = "board_bundle"
    elif any(pattern.search(full_text) for pattern in _COMBO_PATTERNS):
        offer_type = "combo"
    elif any(pattern.search(full_text) for pattern in _BUNDLE_PATTERNS):
        offer_type = "bundle"
    elif "+" in candidate.display_name and any(
        token in full_text.lower() for token in ("cpu", "mb", "主機板", "記憶體", "顯卡")
    ):
        offer_type = "combo"

    pricing_mode = "normal"
    for mode, patterns in _PRICING_MODE_PATTERNS:
        if any(pattern.search(full_text) for pattern in patterns):
            pricing_mode = mode
            break
    if offer_type != "single_part" and pricing_mode == "normal":
        pricing_mode = "unknown"

    market_segment = "unknown"
    if any(pattern.search(full_text) for pattern in _WORKSTATION_PATTERNS):
        market_segment = "workstation"
    elif any(pattern.search(full_text) for pattern in _CREATOR_PATTERNS):
        market_segment = "creator"
    elif any(pattern.search(full_text) for pattern in _GAMING_PATTERNS):
        market_segment = "gaming"
    elif any(pattern.search(full_text) for pattern in _OFFICE_PATTERNS):
        market_segment = "office"

    ram_sale_unit = "unknown"
    if candidate.category == "RAM":
        dimms = _to_int(
            key_specs.get("kit_dimms_hint")
            if isinstance(key_specs, Mapping)
            else None
        )
        if dimms is not None:
            ram_sale_unit = "kit" if dimms > 1 else "single_dimm"
        elif any(pattern.search(full_text) for pattern in _KIT_PATTERNS):
            ram_sale_unit = "kit"
        elif any(pattern.search(full_text) for pattern in _SINGLE_DIMM_PATTERNS):
            ram_sale_unit = "single_dimm"

    return SemanticClassification(
        offer_type=offer_type,
        pricing_mode=pricing_mode,
        market_segment=market_segment,
        ram_sale_unit=ram_sale_unit,
    )


def apply_build_candidate_gate(
    retrieval_result: Any,
    *,
    profile: BuildRequestProfile,
) -> BuildGateResult:
    if not profile.enabled:
        return BuildGateResult(retrieval_result=retrieval_result, events=[])
    if not isinstance(getattr(retrieval_result, "items_by_category", None), dict):
        return BuildGateResult(retrieval_result=retrieval_result, events=[])

    items_by_category = {
        category: list(items)
        for category, items in retrieval_result.items_by_category.items()
    }
    filtered_items, semantic_events = _apply_semantic_filters(items_by_category, profile=profile)
    compatible_items, compatibility_events = _apply_compatibility_filters(filtered_items)
    psu_items, psu_events = _apply_psu_capacity_filters(compatible_items)
    if "PSU" in compatible_items or psu_items:
        compatible_items["PSU"] = psu_items
    return BuildGateResult(
        retrieval_result=P1RetrievalResult(items_by_category=compatible_items),
        events=[*semantic_events, *compatibility_events, *psu_events],
    )


def _apply_semantic_filters(
    items_by_category: Mapping[str, Sequence[CandidatePart]],
    *,
    profile: BuildRequestProfile,
) -> tuple[dict[str, list[CandidatePart]], list[dict[str, str]]]:
    classified = {
        category: [(item, classify_candidate(item)) for item in items]
        for category, items in items_by_category.items()
    }
    events: list[dict[str, str]] = []
    filtered: dict[str, list[CandidatePart]] = {}

    for category, entries in classified.items():
        kept = list(entries)
        strict_rules: list[tuple[str, Callable[[SemanticClassification], bool]]] = [
            (
                "offer_type",
                lambda c: c.offer_type == "single_part"
                or (
                    c.offer_type == "bundle"
                    and profile.allow_bundle
                )
                or (
                    c.offer_type == "board_bundle"
                    and profile.allow_board_bundle
                ),
            ),
            ("pricing_mode", lambda c: c.pricing_mode not in {"搭板價", "限搭"}),
        ]
        if category == "GPU" and not profile.allow_workstation_gpu:
            strict_rules.append(("market_segment", lambda c: c.market_segment != "workstation"))

        for reason, predicate in strict_rules:
            next_kept = [(item, cls) for item, cls in kept if predicate(cls)]
            if next_kept:
                if len(next_kept) != len(kept):
                    events.append(
                        {
                            "stage": "semantic_filter",
                            "category": category,
                            "reason": reason,
                            "action": "drop",
                            "dropped_count": str(len(kept) - len(next_kept)),
                        }
                    )
                kept = next_kept
            elif kept:
                events.append(
                    {
                        "stage": "semantic_filter",
                        "category": category,
                        "reason": reason,
                        "action": "relaxed",
                        "dropped_count": "0",
                    }
                )

        if category == "RAM":
            kits = [(item, cls) for item, cls in kept if cls.ram_sale_unit == "kit"]
            if kits:
                single_dimms = [item for item, cls in kept if cls.ram_sale_unit == "single_dimm"]
                if single_dimms:
                    events.append(
                        {
                            "stage": "semantic_filter",
                            "category": category,
                            "reason": "ram_sale_unit",
                            "action": "drop",
                            "dropped_count": str(len(single_dimms)),
                        }
                    )
                kept = [entry for entry in kept if entry[1].ram_sale_unit != "single_dimm"]
            elif any(cls.ram_sale_unit == "single_dimm" for _, cls in kept):
                events.append(
                    {
                        "stage": "semantic_filter",
                        "category": category,
                        "reason": "ram_sale_unit",
                        "action": "relaxed",
                        "dropped_count": "0",
                    }
                )

        filtered[category] = [item for item, _ in kept]
    return filtered, events


def _apply_compatibility_filters(
    items_by_category: Mapping[str, Sequence[CandidatePart]],
) -> tuple[dict[str, list[CandidatePart]], list[dict[str, str]]]:
    current = {category: list(items) for category, items in items_by_category.items()}
    events: list[dict[str, str]] = []
    rules = (
        ("CPU", "MB", _cpu_mb_status, "cpu_mb"),
        ("MB", "RAM", _mb_ram_status, "mb_ram"),
        ("MB", "CASE", _mb_case_status, "mb_case"),
        ("GPU", "CASE", _gpu_case_status, "gpu_case"),
        ("COOLER", "CASE", _cooler_case_status, "cooler_case"),
    )

    changed = True
    while changed:
        changed = False
        for left_category, right_category, checker, rule_name in rules:
            left_items = current.get(left_category)
            right_items = current.get(right_category)
            if not left_items or not right_items:
                continue
            left_kept, dropped_count = _filter_compatible_side(
                left_items,
                right_items,
                checker=checker,
            )
            if dropped_count:
                current[left_category] = left_kept
                events.append(
                    {
                        "stage": "compatibility_gate",
                        "category": left_category,
                        "reason": rule_name,
                        "action": "drop",
                        "dropped_count": str(dropped_count),
                    }
                )
                changed = True

            left_items = current.get(left_category)
            right_items = current.get(right_category)
            if not left_items or not right_items:
                continue
            right_kept, dropped_count = _filter_compatible_side(
                right_items,
                left_items,
                checker=lambda item, counterpart: checker(counterpart, item),
            )
            if dropped_count:
                current[right_category] = right_kept
                events.append(
                    {
                        "stage": "compatibility_gate",
                        "category": right_category,
                        "reason": rule_name,
                        "action": "drop",
                        "dropped_count": str(dropped_count),
                    }
                )
                changed = True
    return current, events


def _estimate_required_psu_wattage(
    *,
    cpu: CandidatePart | None,
    gpu: CandidatePart | None,
) -> int | None:
    cpu_specs = cpu.key_specs if cpu is not None and isinstance(cpu.key_specs, Mapping) else {}
    gpu_specs = gpu.key_specs if gpu is not None and isinstance(gpu.key_specs, Mapping) else {}
    cpu_tdp = _to_int(cpu_specs.get("tdp")) or _to_int(cpu_specs.get("tdp_hint"))
    gpu_power = _to_int(gpu_specs.get("power_w")) or _to_int(gpu_specs.get("power_w_hint"))

    if cpu_tdp is None and gpu_power is None:
        return None

    base = 150
    total = base
    if cpu_tdp is not None:
        total += cpu_tdp
    if gpu_power is not None:
        total += gpu_power
    rounded = int((total + 49) / 50) * 50
    return rounded


def estimate_required_psu_wattage(
    *,
    cpu: CandidatePart | None,
    gpu: CandidatePart | None,
) -> int | None:
    return _estimate_required_psu_wattage(cpu=cpu, gpu=gpu)


def _apply_psu_capacity_filters(
    items_by_category: Mapping[str, Sequence[CandidatePart]],
) -> tuple[list[CandidatePart], list[dict[str, str]]]:
    psus = list(items_by_category.get("PSU", []))
    if not psus:
        return psus, []

    cpus = list(items_by_category.get("CPU", []))
    gpus = list(items_by_category.get("GPU", []))
    workloads: list[tuple[CandidatePart | None, CandidatePart | None]] = []
    if cpus and gpus:
        workloads.extend((cpu, gpu) for cpu in cpus for gpu in gpus)
    elif cpus:
        workloads.extend((cpu, None) for cpu in cpus)
    elif gpus:
        workloads.extend((None, gpu) for gpu in gpus)
    else:
        return psus, []

    kept: list[CandidatePart] = []
    dropped_count = 0
    for psu in psus:
        specs = psu.key_specs if isinstance(psu.key_specs, Mapping) else {}
        wattage = _to_int(specs.get("wattage_w")) or _to_int(specs.get("wattage_w_hint"))
        if wattage is None:
            kept.append(psu)
            continue

        requirements = [
            requirement
            for requirement in (
                _estimate_required_psu_wattage(cpu=cpu, gpu=gpu)
                for cpu, gpu in workloads
            )
            if requirement is not None
        ]
        if not requirements:
            kept.append(psu)
            continue
        if any(wattage >= requirement for requirement in requirements):
            kept.append(psu)
            continue
        dropped_count += 1

    events: list[dict[str, str]] = []
    if dropped_count:
        events.append(
            {
                "stage": "compatibility_gate",
                "category": "PSU",
                "reason": "psu_capacity",
                "action": "drop",
                "dropped_count": str(dropped_count),
            }
        )
    return kept, events


def _filter_compatible_side(
    items: Sequence[CandidatePart],
    opposite_items: Sequence[CandidatePart],
    *,
    checker: Callable[[CandidatePart, CandidatePart], str],
) -> tuple[list[CandidatePart], int]:
    kept: list[CandidatePart] = []
    dropped_count = 0
    for item in items:
        statuses = [checker(item, opposite) for opposite in opposite_items]
        if "compatible" in statuses or "unknown" in statuses:
            kept.append(item)
            continue
        dropped_count += 1
    return kept, dropped_count


def _normalize_socket(specs: Mapping[str, Any]) -> str | None:
    for key in ("socket", "socket_hint"):
        value = _normalize_text(specs.get(key))
        if not value:
            continue
        normalized = value.upper().replace("SOCKET", "").strip()
        if normalized:
            return normalized
    return None


def _normalize_memory_type(specs: Mapping[str, Any]) -> str | None:
    for key in ("memory_type", "memory_type_hint", "ddr_gen", "ddr_gen_hint"):
        value = _normalize_text(specs.get(key)).upper()
        if "DDR5" in value:
            return "DDR5"
        if "DDR4" in value:
            return "DDR4"
        if "DDR3" in value:
            return "DDR3"
    return None


def _normalize_form_factor(value: Any) -> str | None:
    token = _normalize_upper_token(value)
    return _FORM_FACTOR_ALIASES.get(token)


def _case_supported_form_factors(specs: Mapping[str, Any]) -> set[str] | None:
    raw_support = _normalize_text(specs.get("mb_form_factor_support_hint"))
    supported: set[str] = set()
    if raw_support:
        for raw_part in re.split(r"[/,|+ ]+", raw_support):
            normalized = _normalize_form_factor(raw_part)
            if normalized:
                supported.add(normalized)
    if supported:
        return supported

    form_factor_hint = _normalize_text(specs.get("form_factor_hint")).upper()
    if "FULL" in form_factor_hint:
        return set(_CASE_CLASS_SUPPORT["FULL-TOWER"])
    if "MID" in form_factor_hint:
        return set(_CASE_CLASS_SUPPORT["MID-TOWER"])
    if "MINI" in form_factor_hint:
        return set(_CASE_CLASS_SUPPORT["MINI-TOWER"])
    if "SFF" in form_factor_hint or "ITX" in form_factor_hint:
        return set(_CASE_CLASS_SUPPORT["SFF"])
    normalized = _normalize_form_factor(form_factor_hint)
    if normalized:
        return {normalized}
    return None


def _to_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(round(value))
    match = re.search(r"\d+", _normalize_text(value))
    if match is None:
        return None
    return int(match.group(0))


def _cpu_supported_memory_types(cpu: CandidatePart) -> set[str] | None:
    specs = cpu.key_specs if isinstance(cpu.key_specs, Mapping) else {}
    direct_memory = _normalize_memory_type(specs)
    if direct_memory is not None:
        return {direct_memory}
    socket = _normalize_socket(specs)
    if socket is None:
        return None
    return _CPU_SOCKET_MEMORY_SUPPORT.get(socket.upper())


def _cpu_mb_status(cpu: CandidatePart, motherboard: CandidatePart) -> str:
    cpu_specs = cpu.key_specs if isinstance(cpu.key_specs, Mapping) else {}
    mb_specs = motherboard.key_specs if isinstance(motherboard.key_specs, Mapping) else {}

    cpu_socket = _normalize_socket(cpu_specs)
    mb_socket = _normalize_socket(mb_specs)
    if cpu_socket and mb_socket and cpu_socket != mb_socket:
        return "incompatible"

    cpu_memory = _cpu_supported_memory_types(cpu)
    mb_memory = _normalize_memory_type(mb_specs)
    if cpu_memory and mb_memory and mb_memory not in cpu_memory:
        return "incompatible"

    if cpu_socket and mb_socket:
        return "compatible"
    if cpu_memory and mb_memory:
        return "compatible"
    return "unknown"


def _mb_ram_status(motherboard: CandidatePart, ram: CandidatePart) -> str:
    mb_specs = motherboard.key_specs if isinstance(motherboard.key_specs, Mapping) else {}
    ram_specs = ram.key_specs if isinstance(ram.key_specs, Mapping) else {}
    mb_memory = _normalize_memory_type(mb_specs)
    ram_memory = _normalize_memory_type(ram_specs)
    if mb_memory and ram_memory and mb_memory != ram_memory:
        return "incompatible"
    if mb_memory and ram_memory:
        return "compatible"
    return "unknown"


def _mb_case_status(motherboard: CandidatePart, case: CandidatePart) -> str:
    mb_specs = motherboard.key_specs if isinstance(motherboard.key_specs, Mapping) else {}
    case_specs = case.key_specs if isinstance(case.key_specs, Mapping) else {}
    mb_form_factor = _normalize_form_factor(mb_specs.get("form_factor")) or _normalize_form_factor(
        mb_specs.get("form_factor_hint")
    )
    supported = _case_supported_form_factors(case_specs)
    if mb_form_factor and supported and mb_form_factor not in supported:
        return "incompatible"
    if mb_form_factor and supported:
        return "compatible"
    return "unknown"


def _gpu_case_status(gpu: CandidatePart, case: CandidatePart) -> str:
    gpu_specs = gpu.key_specs if isinstance(gpu.key_specs, Mapping) else {}
    case_specs = case.key_specs if isinstance(case.key_specs, Mapping) else {}
    gpu_length = _to_int(gpu_specs.get("length_mm")) or _to_int(gpu_specs.get("length_mm_hint"))
    case_limit = _to_int(case_specs.get("gpu_max_length_mm")) or _to_int(
        case_specs.get("gpu_max_length_mm_hint")
    )
    if gpu_length is not None and case_limit is not None and gpu_length > case_limit:
        return "incompatible"
    if gpu_length is not None and case_limit is not None:
        return "compatible"
    return "unknown"


def _cooler_case_status(cooler: CandidatePart, case: CandidatePart) -> str:
    cooler_specs = cooler.key_specs if isinstance(cooler.key_specs, Mapping) else {}
    case_specs = case.key_specs if isinstance(case.key_specs, Mapping) else {}
    cooler_height = _to_int(cooler_specs.get("height_mm")) or _to_int(cooler_specs.get("height_mm_hint"))
    case_limit = _to_int(case_specs.get("cpu_cooler_max_height_mm")) or _to_int(
        case_specs.get("cpu_cooler_max_height_mm_hint")
    )
    if cooler_height is not None and case_limit is not None and cooler_height > case_limit:
        return "incompatible"
    if cooler_height is not None and case_limit is not None:
        return "compatible"
    return "unknown"


def evaluate_build_selection_compatibility(
    parts_by_category: Mapping[str, CandidatePart | None],
) -> list[str]:
    reasons: list[str] = []

    cpu = parts_by_category.get("CPU")
    motherboard = parts_by_category.get("MB")
    ram = parts_by_category.get("RAM")
    gpu = parts_by_category.get("GPU")
    case = parts_by_category.get("CASE")
    cooler = parts_by_category.get("COOLER")
    psu = parts_by_category.get("PSU")

    if cpu is not None and motherboard is not None and _cpu_mb_status(cpu, motherboard) == "incompatible":
        reasons.append("cpu_mb")
    if motherboard is not None and ram is not None and _mb_ram_status(motherboard, ram) == "incompatible":
        reasons.append("mb_ram")
    if motherboard is not None and case is not None and _mb_case_status(motherboard, case) == "incompatible":
        reasons.append("mb_case")
    if gpu is not None and case is not None and _gpu_case_status(gpu, case) == "incompatible":
        reasons.append("gpu_case")
    if cooler is not None and case is not None and _cooler_case_status(cooler, case) == "incompatible":
        reasons.append("cooler_case")
    if psu is not None:
        specs = psu.key_specs if isinstance(psu.key_specs, Mapping) else {}
        wattage = _to_int(specs.get("wattage_w")) or _to_int(specs.get("wattage_w_hint"))
        required = _estimate_required_psu_wattage(cpu=cpu, gpu=gpu)
        if wattage is not None and required is not None and wattage < required:
            reasons.append("psu_capacity")
    return reasons


__all__ = [
    "BuildGateResult",
    "BuildRequestProfile",
    "SemanticClassification",
    "apply_build_candidate_gate",
    "build_request_profile",
    "classify_candidate",
    "estimate_required_psu_wattage",
    "evaluate_build_selection_compatibility",
]
