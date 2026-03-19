from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Callable, Mapping, Sequence

from backend.services.chat.contracts import ChatMessage, NormalizedDemand
from backend.services.chat.provider.models import ProviderCallResult

_NORMALIZATION_MAX_HISTORY = 6
_BUILD_PATTERNS = (
    re.compile(r"配\s*單"),
    re.compile(r"配\s*置"),
    re.compile(r"組\s*(?:一?台)?\s*(?:電腦|主機|機)"),
    re.compile(r"組.*(?:電腦|主機|機)"),
    re.compile(r"配.*(?:電腦|主機|機)"),
    re.compile(r"整\s*機"),
    re.compile(r"遊\s*戲\s*機"),
    re.compile(r"文\s*書\s*機"),
)
_UPGRADE_PATTERNS = (
    re.compile(r"升\s*級"),
    re.compile(r"保\s*留"),
    re.compile(r"沿\s*用"),
    re.compile(r"換(?:掉|成)?"),
)
_CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "CPU": ("cpu", "處理器", "ryzen", "core i"),
    "GPU": ("gpu", "顯卡", "rtx", "gtx", "radeon", "arc"),
    "MB": ("mb", "主機板", "motherboard"),
    "RAM": ("ram", "記憶體", "ddr4", "ddr5"),
    "SSD": ("ssd", "固態", "nvme", "m.2"),
    "PSU": ("psu", "電供", "電源"),
    "CASE": ("case", "機殼", "機箱"),
}
_USAGE_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("gaming", ("遊戲", "3a", "gaming", "電競")),
    ("office", ("文書", "office", "上網", "商用")),
    ("creator", ("剪輯", "創作", "creator", "渲染", "stream")),
    ("workstation", ("工作站", "cad", "workstation", "專業繪圖")),
)
_CPU_VENDOR_KEYWORDS = {
    "AMD": ("amd", "ryzen"),
    "Intel": ("intel", "core i", "ultra "),
}
_GPU_VENDOR_KEYWORDS = {
    "NVIDIA": ("nvidia", "geforce", "rtx", "gtx"),
    "AMD": ("amd", "radeon", "rx "),
    "Intel": ("intel", "arc"),
}
_SIZE_KEYWORDS = {
    "ITX": ("itx", "mini-itx"),
    "mATX": ("matx", "micro-atx", "m-atx"),
    "ATX": ("atx",),
}
_EXPLANATION_STYLE_KEYWORDS = {
    "brief": ("簡短", "簡單", "一句話", "重點"),
    "detailed": ("詳細", "完整", "分析", "細講"),
}
_DISALLOW_BUNDLE_PATTERNS = (
    re.compile(r"不要\s*組合"),
    re.compile(r"不要\s*套裝"),
    re.compile(r"只要\s*單品"),
)
_BUDGET_PATTERN = re.compile(r"(\d+(?:\.\d+)?)\s*(萬|w|k|千|元|塊)")
_PRODUCT_PATTERNS = (
    re.compile(r"\b(?:rtx|gtx|rx|arc)\s*[a-z]?\d{3,4}(?:\s*ti|\s*super)?\b", re.IGNORECASE),
    re.compile(r"\bryzen\s*\d\s*\d{3,4}[a-z]{0,2}\b", re.IGNORECASE),
    re.compile(r"\bcore\s*i[3579][-\s]?\d{3,5}[a-z]{0,3}\b", re.IGNORECASE),
)
_JSON_BLOCK_PATTERN = re.compile(r"\{.*\}", re.DOTALL)

_NORMALIZATION_PROMPT = """你是 PC 組裝需求正規化器。你的任務是把使用者意圖轉成 NormalizedDemand JSON，不是直接回覆購買建議。

規則：
1. 只輸出一個 JSON object，不要輸出說明文字、markdown、程式碼框或推薦內容。
2. 不要推薦任何零件。
3. 不要補不存在的預算；不清楚就填 unknown 或 null，並把缺失資訊寫進 missing_information。
4. categories 必須只用 CPU/GPU/MB/RAM/SSD/PSU/CASE。
5. build / upgrade 預設 allow_bundle=false、allow_board_bundle=false、allow_workstation_gpu=false。
6. 若使用者說「幫我配一台 4 萬內遊戲機，想要 AMD CPU + NVIDIA 顯卡」：
   request_mode 必須是 build，usage_profile 必須是 gaming，budget_max=40000，preferred_cpu_vendor=AMD，preferred_gpu_vendor=NVIDIA，allow_workstation_gpu=false。
7. 若使用者說「幫我找 2 萬左右的 RTX 5070 顯卡」：
   request_mode 必須是 single_part，categories 必須包含 GPU，budget_target 應接近 20000，query_focus 應保留 RTX 5070。
8. 若使用者說「最近有推薦的 Ryzen 9700X CPU 嗎」：
   request_mode 必須是 single_part，categories 必須包含 CPU，query_focus 應保留 Ryzen 9700X，不可轉成整機。
9. 必須填完整 schema keys；沒有資訊時用 null、unknown 或空陣列。
"""

_JSON_REPAIR_PROMPT = """你是 JSON 修復器。請把輸入內容修復成單一有效 JSON object，必須符合 NormalizedDemand 結構。
只輸出 JSON，不要有任何說明。若資料不足，保留 null、unknown 或空陣列。"""


@dataclass(slots=True)
class DemandNormalizationResult:
    normalized_demand: NormalizedDemand
    fallback_used: bool
    report: dict[str, Any]


def _normalize_text(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _recent_history(history: Sequence[ChatMessage] | None) -> list[ChatMessage]:
    if not history:
        return []
    turns = [turn for turn in history if turn.content.strip()]
    return turns[-_NORMALIZATION_MAX_HISTORY:]


def _json_schema_payload() -> dict[str, object]:
    return {
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "normalized_demand",
                "strict": True,
                "schema": NormalizedDemand.model_json_schema(),
            },
        }
    }


def _build_normalization_messages(
    *,
    message_text: str,
    history: Sequence[ChatMessage] | None,
    explicit_demand: Mapping[str, Any] | None,
    prompt: str,
) -> list[dict[str, str]]:
    history_lines = [
        f"{turn.role}: {turn.content}"
        for turn in _recent_history(history)
    ]
    explicit_json = (
        json.dumps(dict(explicit_demand), ensure_ascii=False, sort_keys=True)
        if explicit_demand
        else "null"
    )
    return [
        {"role": "system", "content": prompt},
        {
            "role": "user",
            "content": "\n".join(
                [
                    "USER_TEXT:",
                    message_text.strip() or "(empty)",
                    "",
                    "RECENT_HISTORY:",
                    "\n".join(history_lines) if history_lines else "(none)",
                    "",
                    "EXPLICIT_DEMAND:",
                    explicit_json,
                ]
            ),
        },
    ]


def _extract_json_object(payload: str) -> str | None:
    stripped = payload.strip()
    if not stripped:
        return None
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped
    match = _JSON_BLOCK_PATTERN.search(stripped)
    if match is None:
        return None
    return match.group(0)


def _repair_json_text(payload: str) -> str | None:
    candidate = _extract_json_object(payload)
    if candidate is None:
        return None

    repaired = candidate.replace("“", '"').replace("”", '"').replace("’", "'")
    repaired = repaired.replace("True", "true").replace("False", "false").replace("None", "null")
    repaired = re.sub(r",(\s*[}\]])", r"\1", repaired)
    return repaired


def _validate_normalized_demand(payload: str) -> NormalizedDemand:
    return NormalizedDemand.model_validate_json(payload)


def _try_parse_normalized_demand(
    payload: str,
) -> tuple[NormalizedDemand | None, bool]:
    direct = _extract_json_object(payload)
    if direct is not None:
        try:
            return _validate_normalized_demand(direct), False
        except Exception:
            pass

    repaired = _repair_json_text(payload)
    if repaired is not None:
        try:
            return _validate_normalized_demand(repaired), True
        except Exception:
            return None, True
    return None, False


def _budget_value(number: str, unit: str) -> int | None:
    try:
        raw = float(number)
    except ValueError:
        return None

    unit_lower = unit.lower()
    if unit_lower in {"萬", "w"}:
        raw *= 10000
    elif unit_lower in {"k", "千"}:
        raw *= 1000
    return max(0, int(round(raw)))


def _detect_request_mode(text: str, categories: list[str]) -> str:
    if any(pattern.search(text) for pattern in _UPGRADE_PATTERNS):
        return "upgrade"
    if any(pattern.search(text) for pattern in _BUILD_PATTERNS):
        return "build"
    if categories:
        return "single_part"
    return "unknown"


def _detect_categories(text: str, request_mode: str) -> list[str]:
    categories: list[str] = []
    for category, keywords in _CATEGORY_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            categories.append(category)

    if request_mode == "build":
        ordered = ["CPU", "MB", "RAM", "SSD", "PSU", "CASE"]
        for category in categories:
            if category not in ordered:
                ordered.append(category)
        if "GPU" in categories and "GPU" not in ordered:
            ordered.append("GPU")
        return ordered
    return categories


def _detect_usage_profile(text: str) -> str:
    matched: list[str] = []
    for usage_profile, keywords in _USAGE_KEYWORDS:
        if any(keyword in text for keyword in keywords):
            matched.append(usage_profile)
    if len(matched) > 1:
        return "mixed"
    if matched:
        return matched[0]
    return "unknown"


def _detect_vendor(text: str, *, table: Mapping[str, Sequence[str]]) -> str | None:
    for vendor, keywords in table.items():
        if any(keyword in text for keyword in keywords):
            return vendor
    return None


def _detect_size_preference(text: str) -> str | None:
    for size, keywords in _SIZE_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            return size
    return None


def _detect_explanation_style(text: str) -> str:
    for style, keywords in _EXPLANATION_STYLE_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            return style
    return "normal"


def _detect_query_focus(message_text: str) -> list[str]:
    focus: list[str] = []
    for pattern in _PRODUCT_PATTERNS:
        for match in pattern.findall(message_text):
            normalized = " ".join(str(match).split())
            if normalized not in focus:
                focus.append(normalized)
    return focus


def rule_fallback_normalized_demand(
    *,
    message_text: str,
    history: Sequence[ChatMessage] | None,
) -> NormalizedDemand:
    combined_text = _normalize_text(
        "\n".join(
            part
            for part in [
                *(turn.content for turn in _recent_history(history)),
                message_text,
            ]
            if part.strip()
        )
    )
    categories = _detect_categories(combined_text, "unknown")
    request_mode = _detect_request_mode(combined_text, categories)
    categories = _detect_categories(combined_text, request_mode)

    budgets = [
        _budget_value(number, unit)
        for number, unit in _BUDGET_PATTERN.findall(message_text)
    ]
    budgets = [budget for budget in budgets if budget is not None]
    budget_max = max(budgets) if budgets else None
    budget_flex_pct = 0.1 if "左右" in message_text or "附近" in message_text else None

    demand = NormalizedDemand(
        request_mode=request_mode,
        categories=categories,
        usage_profile=_detect_usage_profile(combined_text),
        budget_max=budget_max,
        budget_target=(
            budgets[0]
            if budgets and ("左右" in message_text or "附近" in message_text)
            else None
        ),
        budget_flex_pct=budget_flex_pct,
        preferred_cpu_vendor=_detect_vendor(combined_text, table=_CPU_VENDOR_KEYWORDS),
        preferred_gpu_vendor=_detect_vendor(combined_text, table=_GPU_VENDOR_KEYWORDS),
        size_preference=_detect_size_preference(combined_text),
        allow_bundle=not any(pattern.search(message_text) for pattern in _DISALLOW_BUNDLE_PATTERNS),
        allow_board_bundle=False,
        allow_workstation_gpu=False,
        explanation_style=_detect_explanation_style(message_text),
        normalization_confidence=0.45 if categories or request_mode != "unknown" else 0.2,
        normalization_source="rule_fallback",
        query_focus=_detect_query_focus(message_text),
    )

    missing_information: list[str] = []
    if demand.request_mode == "build" and demand.budget_max is None:
        missing_information.append("budget")
    if demand.request_mode == "upgrade" and not demand.existing_parts:
        missing_information.append("existing_parts")
    if demand.request_mode == "unknown":
        missing_information.append("request_mode")
    if not demand.categories:
        missing_information.append("categories")
    demand.missing_information = missing_information
    if demand.request_mode in {"build", "upgrade"}:
        demand.allow_bundle = False
        demand.allow_board_bundle = False
        demand.allow_workstation_gpu = False
    return demand


def normalize_explicit_demand(
    raw_demand: Mapping[str, Any] | None,
) -> tuple[NormalizedDemand | None, set[str]]:
    if not raw_demand:
        return None, set()

    normalized_payload: dict[str, Any] = {}
    explicit_fields: set[str] = set()

    def assign(field_name: str, value: Any) -> None:
        normalized_payload[field_name] = value
        explicit_fields.add(field_name)

    raw_filters = raw_demand.get("filters")
    filters = raw_filters if isinstance(raw_filters, Mapping) else {}

    for field_name in (
        "request_mode",
        "usage_profile",
        "budget_max",
        "budget_target",
        "budget_flex_pct",
        "preferred_cpu_vendor",
        "preferred_gpu_vendor",
        "size_preference",
        "brand_preference_hard",
        "brand_preference_soft",
        "disallowed_brands",
        "must_have_features",
        "avoid_features",
        "allow_bundle",
        "allow_board_bundle",
        "allow_workstation_gpu",
        "existing_parts",
        "upgrade_target_parts",
        "explanation_style",
        "missing_information",
        "normalization_confidence",
        "normalization_source",
        "query_focus",
        "categories",
    ):
        if field_name in raw_demand:
            assign(field_name, raw_demand.get(field_name))

    if "budget" in filters and "budget_max" not in normalized_payload:
        assign("budget_max", filters.get("budget"))
    if "max_price" in filters and "budget_max" not in normalized_payload:
        assign("budget_max", filters.get("max_price"))
    if "target_price" in filters and "budget_target" not in normalized_payload:
        assign("budget_target", filters.get("target_price"))
    if "query_text" in filters and "query_focus" not in normalized_payload:
        assign("query_focus", [filters.get("query_text")])

    if not normalized_payload:
        return None, set()

    if "normalization_source" not in normalized_payload:
        normalized_payload["normalization_source"] = "rule_fallback"

    return NormalizedDemand.model_validate(normalized_payload), explicit_fields


def merge_normalized_demands(
    *,
    explicit_demand: NormalizedDemand | None,
    explicit_fields: set[str],
    ai_demand: NormalizedDemand,
) -> tuple[NormalizedDemand, dict[str, Any]]:
    merged = ai_demand.model_dump()
    explicit_payload = explicit_demand.model_dump() if explicit_demand is not None else {}

    conflicts: list[str] = []
    explicit_only: list[str] = []
    ai_only: list[str] = []

    restrictive_boolean_fields = {
        "allow_bundle",
        "allow_board_bundle",
        "allow_workstation_gpu",
    }
    additive_list_fields = {
        "disallowed_brands",
        "must_have_features",
        "avoid_features",
        "missing_information",
        "query_focus",
        "existing_parts",
        "upgrade_target_parts",
    }

    for field_name, explicit_value in explicit_payload.items():
        if field_name not in explicit_fields:
            continue
        ai_value = merged.get(field_name)

        if field_name in restrictive_boolean_fields:
            merged[field_name] = bool(explicit_value) and bool(ai_value)
            if ai_value != explicit_value:
                conflicts.append(field_name)
            explicit_only.append(field_name)
            continue

        if field_name in additive_list_fields:
            combined = []
            for value in [*(explicit_value or []), *(ai_value or [])]:
                if value not in combined:
                    combined.append(value)
            merged[field_name] = combined
            explicit_only.append(field_name)
            continue

        if explicit_value in (None, "", [], "unknown"):
            continue

        if ai_value not in (None, "", [], "unknown") and ai_value != explicit_value:
            conflicts.append(field_name)

        merged[field_name] = explicit_value
        explicit_only.append(field_name)

    for field_name, value in merged.items():
        if field_name in explicit_only:
            continue
        if value not in (None, "", [], "unknown"):
            ai_only.append(field_name)

    merged_demand = NormalizedDemand.model_validate(merged)
    if merged_demand.request_mode in {"build", "upgrade"}:
        merged_demand.allow_bundle = False if "allow_bundle" not in explicit_fields else merged_demand.allow_bundle
        merged_demand.allow_board_bundle = (
            False if "allow_board_bundle" not in explicit_fields else merged_demand.allow_board_bundle
        )
        merged_demand.allow_workstation_gpu = (
            False
            if "allow_workstation_gpu" not in explicit_fields
            else merged_demand.allow_workstation_gpu
        )

    return merged_demand, {
        "explicit_fields": sorted(explicit_fields),
        "merged_from_explicit": sorted(set(explicit_only)),
        "merged_from_ai": sorted(set(ai_only)),
        "conflicts": sorted(set(conflicts)),
    }


def run_normalization_pass(
    *,
    message_text: str,
    history: Sequence[ChatMessage] | None,
    explicit_demand: Mapping[str, Any] | None,
    settings: object,
    request_id: str,
    generate_provider_result: Callable[..., ProviderCallResult],
    log_operation: Callable[..., Any],
) -> DemandNormalizationResult:
    fallback_used = False
    provider_name = str(getattr(settings, "ai_provider", ""))
    structured_messages = _build_normalization_messages(
        message_text=message_text,
        history=history,
        explicit_demand=explicit_demand,
        prompt=_NORMALIZATION_PROMPT,
    )

    if "openai_compat" in provider_name:
        try:
            provider_result = generate_provider_result(
                settings=settings,
                messages=structured_messages,
                request_id=f"{request_id}:normalize:structured",
                extra_payload=_json_schema_payload(),
            )
            parsed, repaired = _try_parse_normalized_demand(provider_result.text)
            if parsed is not None:
                parsed.normalization_source = "ai_repaired_json" if repaired else "ai_structured"
                return DemandNormalizationResult(
                    normalized_demand=parsed,
                    fallback_used=False,
                    report={
                        "source": parsed.normalization_source,
                        "confidence": parsed.normalization_confidence,
                        "missing_information": list(parsed.missing_information),
                        "fallback_used": False,
                        "merge_trace": {},
                    },
                )
            fallback_used = True
        except Exception as exc:
            fallback_used = True
            log_operation(
                "normalization_structured_unsupported",
                request_id=request_id,
                provider=provider_name,
                model=str(getattr(settings, "ai_model", "")),
                error_type=type(exc).__name__,
            )

    try:
        provider_result = generate_provider_result(
            settings=settings,
            messages=structured_messages,
            request_id=f"{request_id}:normalize:json",
        )
        parsed, repaired = _try_parse_normalized_demand(provider_result.text)
        if parsed is not None:
            parsed.normalization_source = "ai_repaired_json" if repaired or fallback_used else "ai_structured"
            return DemandNormalizationResult(
                normalized_demand=parsed,
                fallback_used=True if fallback_used or repaired else False,
                report={
                    "source": parsed.normalization_source,
                    "confidence": parsed.normalization_confidence,
                    "missing_information": list(parsed.missing_information),
                    "fallback_used": True if fallback_used or repaired else False,
                    "merge_trace": {},
                },
            )
    except Exception as exc:
        fallback_used = True
        log_operation(
            "normalization_json_failed",
            request_id=request_id,
            provider=provider_name,
            model=str(getattr(settings, "ai_model", "")),
            error_type=type(exc).__name__,
        )

    try:
        repair_messages = [
            {"role": "system", "content": _JSON_REPAIR_PROMPT},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "invalid_payload": provider_result.text if "provider_result" in locals() else "",
                        "schema": NormalizedDemand.model_json_schema(),
                    },
                    ensure_ascii=False,
                ),
            },
        ]
        repaired_result = generate_provider_result(
            settings=settings,
            messages=repair_messages,
            request_id=f"{request_id}:normalize:repair",
        )
        parsed, _ = _try_parse_normalized_demand(repaired_result.text)
        if parsed is not None:
            parsed.normalization_source = "ai_repaired_json"
            return DemandNormalizationResult(
                normalized_demand=parsed,
                fallback_used=True,
                report={
                    "source": "ai_repaired_json",
                    "confidence": parsed.normalization_confidence,
                    "missing_information": list(parsed.missing_information),
                    "fallback_used": True,
                    "merge_trace": {},
                },
            )
    except Exception as exc:
        log_operation(
            "normalization_repair_failed",
            request_id=request_id,
            provider=provider_name,
            model=str(getattr(settings, "ai_model", "")),
            error_type=type(exc).__name__,
        )

    fallback = rule_fallback_normalized_demand(
        message_text=message_text,
        history=history,
    )
    return DemandNormalizationResult(
        normalized_demand=fallback,
        fallback_used=True,
        report={
            "source": "rule_fallback",
            "confidence": fallback.normalization_confidence,
            "missing_information": list(fallback.missing_information),
            "fallback_used": True,
            "merge_trace": {},
        },
    )


__all__ = [
    "DemandNormalizationResult",
    "merge_normalized_demands",
    "normalize_explicit_demand",
    "rule_fallback_normalized_demand",
    "run_normalization_pass",
]
