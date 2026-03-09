# backend/services/chat/dq.py
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import re
from typing import Any


MIN_RESPONSE_CHARS = 2
HIGH_REPETITION_RATIO = 0.6
LOW_UNIQUE_LINE_RATIO = 0.5
MIN_CONTEXT_HIT_COUNT = 1
UNSURE_KEYWORDS = (
    "不知道",
    "無法回答",
    "不確定",
    "資料不足",
    "無法判斷",
    "不清楚",
)
NEXT_STEP_KEYWORDS = (
    "請補充",
    "請提供",
    "提供",
    "告訴我",
    "補充",
    "預算",
    "用途",
    "需求",
    "再試",
    "建議",
)
CATEGORY_HINTS: dict[str, tuple[str, ...]] = {
    "CPU": ("cpu", "處理器"),
    "MB": ("mb", "主機板", "主板"),
    "GPU": ("gpu", "顯卡"),
    "RAM": ("ram", "記憶體"),
    "SSD": ("ssd", "固態硬碟"),
    "PSU": ("psu", "電源", "電源供應器"),
    "CASE": ("case", "機殼", "機箱"),
}
TOKEN_RE = re.compile(r"[a-z0-9.+-]{2,}|[\u4e00-\u9fff]{2,}", re.IGNORECASE)
SEGMENT_SPLIT_RE = re.compile(r"[\n。！？!?]+")


@dataclass(slots=True)
class DQReport:
    passed: bool
    reasons: list[str]
    warnings: list[str]
    metrics: dict[str, float | int | str | bool]
    quarantine: bool


def _append_unique(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _split_segments(text: str) -> list[str]:
    return [segment.strip() for segment in SEGMENT_SPLIT_RE.split(text) if segment.strip()]


def _extract_candidate_tokens(
    request_categories: list[str],
    compressed_candidates: dict[str, list[dict[str, object]]],
) -> set[str]:
    tokens: set[str] = set()

    for category in request_categories:
        for hint in CATEGORY_HINTS.get(category, (category.lower(),)):
            normalized = hint.strip().lower()
            if normalized:
                tokens.add(normalized)

    for category, items in compressed_candidates.items():
        for hint in CATEGORY_HINTS.get(category, (category.lower(),)):
            normalized = hint.strip().lower()
            if normalized:
                tokens.add(normalized)

        for item in items:
            display_name = item.get("display_name")
            if isinstance(display_name, str):
                for token in TOKEN_RE.findall(display_name.lower()):
                    tokens.add(token)

            key_specs = item.get("key_specs")
            if isinstance(key_specs, dict):
                for key in key_specs.keys():
                    normalized_key = str(key).strip().lower()
                    if normalized_key:
                        tokens.add(normalized_key)

    return {token for token in tokens if token}


def _keyword_hit_count(text: str, tokens: set[str]) -> int:
    lowered = text.lower()
    return sum(1 for token in tokens if token in lowered)


def _mb_candidates_missing_socket(
    compressed_candidates: dict[str, list[dict[str, object]]],
) -> bool:
    mb_items = compressed_candidates.get("MB") or []
    if not mb_items:
        return False

    for item in mb_items:
        key_specs = item.get("key_specs")
        if not isinstance(key_specs, dict):
            continue
        if any("socket" in str(key).strip().lower() for key in key_specs.keys()):
            return False
    return True


def evaluate_text_dq(
    *,
    text: str,
    request_categories: list[str],
    compressed_candidates: dict[str, list[dict[str, object]]],
    context_pack_text: str | None,
    triggered_retrieval: bool,
) -> DQReport:
    stripped_text = text.strip()
    reasons: list[str] = []
    warnings: list[str] = []

    if len(stripped_text) < MIN_RESPONSE_CHARS:
        _append_unique(reasons, "too_short")

    if any(keyword in stripped_text for keyword in UNSURE_KEYWORDS) and not any(
        keyword in stripped_text for keyword in NEXT_STEP_KEYWORDS
    ):
        _append_unique(reasons, "unsure_without_next_step")

    segments = _split_segments(text)
    if segments:
        counts = Counter(segments)
        unique_line_ratio = len(counts) / len(segments)
        repeated_line_ratio = max(counts.values()) / len(segments)
    else:
        unique_line_ratio = 1.0
        repeated_line_ratio = 0.0

    if len(segments) >= 3 and (
        repeated_line_ratio >= HIGH_REPETITION_RATIO
        or unique_line_ratio <= LOW_UNIQUE_LINE_RATIO
    ):
        _append_unique(reasons, "high_repetition")

    keyword_pool: set[str] = set()
    keyword_hit_count = 0
    if triggered_retrieval:
        for category in request_categories:
            if not compressed_candidates.get(category):
                _append_unique(reasons, "context_category_empty")
                break

        if "MB" in request_categories and _mb_candidates_missing_socket(compressed_candidates):
            _append_unique(reasons, "context_missing_required_specs")

        keyword_pool = _extract_candidate_tokens(request_categories, compressed_candidates)
        if not keyword_pool:
            _append_unique(warnings, "dq_keyword_pool_empty")
        else:
            keyword_hit_count = _keyword_hit_count(text, keyword_pool)
            if compressed_candidates and keyword_hit_count < MIN_CONTEXT_HIT_COUNT:
                _append_unique(reasons, "low_context_hit")

    metrics: dict[str, float | int | str | bool] = {
        "text_length": len(text),
        "stripped_length": len(stripped_text),
        "unique_line_ratio": round(unique_line_ratio, 4),
        "repeated_line_ratio": round(repeated_line_ratio, 4),
        "keyword_hit_count": keyword_hit_count,
        "keyword_pool_size": len(keyword_pool),
        "triggered_retrieval": triggered_retrieval,
        "has_context_pack": bool(context_pack_text),
    }

    return DQReport(
        passed=not reasons,
        reasons=reasons,
        warnings=warnings,
        metrics=metrics,
        quarantine=bool(reasons),
    )
