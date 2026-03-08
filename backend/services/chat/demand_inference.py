# backend/services/chat/demand_inference.py
from __future__ import annotations

import re
from typing import Sequence

from backend.services.chat.contracts import ChatMessage

_DEFAULT_TOP_K = 2
_DEFAULT_ENV = "prod"
_RECENT_USER_TURNS = 2
_DEFAULT_BUILD_CATEGORIES = ("CPU", "MB", "RAM", "SSD", "PSU", "CASE")
_CATEGORY_ORDER = _DEFAULT_BUILD_CATEGORIES + ("GPU",)
_BUDGET_SIGNAL_RE = re.compile(r"(?:^|\D)\d+(?:\.\d+)?\s*(?:萬|w|k|千|元|塊)", re.IGNORECASE)
_BUILD_INTENT_PATTERNS = (
    re.compile(r"配\s*單"),
    re.compile(r"組\s*(?:一?台)?\s*(?:電腦|主機|機)"),
    re.compile(r"整\s*機"),
    re.compile(r"文\s*書\s*機"),
    re.compile(r"遊\s*戲\s*機"),
    re.compile(r"工\s*作\s*站"),
    re.compile(r"預\s*算"),
    re.compile(r"主機(?!板)"),
)
_GPU_INTENT_PATTERNS = (
    re.compile(r"獨\s*顯"),
    re.compile(r"遊\s*戲"),
    re.compile(r"\b(?:rtx|gtx|radeon)\b", re.IGNORECASE),
    re.compile(r"3a", re.IGNORECASE),
    re.compile(r"繪圖"),
)
_NO_GPU_PATTERNS = (
    re.compile(r"不(?:要|用|需要)\s*顯卡"),
    re.compile(r"不含\s*顯卡"),
    re.compile(r"無\s*顯卡"),
    re.compile(r"內\s*顯"),
)
_CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "CPU": ("cpu", "處理器"),
    "MB": ("mb", "主機板", "motherboard"),
    "GPU": ("gpu", "顯卡", "獨顯", "rtx", "gtx", "radeon"),
    "RAM": ("ram", "記憶體"),
    "SSD": ("ssd", "固態", "nvme", "m.2"),
    "PSU": ("psu", "電供", "火牛"),
    "CASE": ("機殼", "chassis", "case"),
}


def _normalize_text(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _recent_user_text(history: Sequence[ChatMessage] | None) -> str:
    if not history:
        return ""

    user_turns = [
        message.content
        for message in history
        if message.role == "user" and message.content.strip()
    ]
    if not user_turns:
        return ""
    return "\n".join(user_turns[-_RECENT_USER_TURNS :])


def _contains_pattern(text: str, patterns: Sequence[re.Pattern[str]]) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def _detect_categories(text: str) -> list[str]:
    categories: list[str] = []
    for category in _CATEGORY_ORDER:
        keywords = _CATEGORY_KEYWORDS.get(category, ())
        if any(keyword in text for keyword in keywords):
            categories.append(category)
    return categories


def infer_chat_demand(
    message: str,
    history: Sequence[ChatMessage] | None = None,
) -> dict[str, object] | None:
    current_message = message.strip()
    if not current_message:
        return None

    recent_history = _recent_user_text(history)
    combined_text = _normalize_text(
        "\n".join(part for part in (recent_history, current_message) if part.strip())
    )
    if not combined_text:
        return None

    categories = _detect_categories(combined_text)
    has_build_intent = _contains_pattern(combined_text, _BUILD_INTENT_PATTERNS)
    has_budget_signal = bool(_BUDGET_SIGNAL_RE.search(combined_text))
    wants_gpu = _contains_pattern(combined_text, _GPU_INTENT_PATTERNS)
    avoids_gpu = _contains_pattern(combined_text, _NO_GPU_PATTERNS)

    if "GPU" in categories and avoids_gpu and not wants_gpu:
        categories = [category for category in categories if category != "GPU"]

    if categories:
        if has_build_intent or has_budget_signal:
            merged_categories = list(_DEFAULT_BUILD_CATEGORIES)
            for category in categories:
                if category not in merged_categories:
                    merged_categories.append(category)
            if wants_gpu and "GPU" not in merged_categories:
                merged_categories.append("GPU")
            return {
                "categories": merged_categories,
                "top_k": _DEFAULT_TOP_K,
                "env": _DEFAULT_ENV,
            }
        return {
            "categories": categories,
            "top_k": _DEFAULT_TOP_K,
            "env": _DEFAULT_ENV,
        }

    if not (has_build_intent or has_budget_signal):
        return None

    inferred_categories = list(_DEFAULT_BUILD_CATEGORIES)
    if wants_gpu and not avoids_gpu:
        inferred_categories.append("GPU")
    return {
        "categories": inferred_categories,
        "top_k": _DEFAULT_TOP_K,
        "env": _DEFAULT_ENV,
    }
