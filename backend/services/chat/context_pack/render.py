# backend/services/chat/context_pack/render.py
from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence, TypedDict

from backend.services.chat.contracts import P3ContextPack


class CompressedCandidate(TypedDict, total=False):
    part_id: str
    category: str
    display_name: str
    key_specs: dict[str, Any]
    price: int | float | None
    source: str
    source_url: str
    snapshot_id: str | None
    run_id: str | None


def _normalize_inline_text(value: Any) -> str: # 把多個空白字符（包括換行符）替換為單個空格，並去除首尾空白
    return " ".join(str(value).split())


def _normalize_url_text(value: Any) -> str: # 移除URL中的\r和\n並去除首尾空白，避免渲染時換行破壞一行卡片的格式
    return str(value).replace("\r", "").replace("\n", "").strip()


def _normalize_spec_value(value: Any) -> str: # 把規格值轉換為字符串，對於None或空字符串返回"-"，對於布林值返回"true"/"false"，對於數字直接轉字符串，對於其他字符串進行內聯文本規範化
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return _normalize_inline_text(value)


def _normalize_price_value(value: Any) -> str: # 把價格值轉換為字符串，對於None或空字符串返回"-"，對於數字直接轉字符串，對於其他字符串進行內聯文本規範化
    if value is None:
        return "-"
    if isinstance(value, str) and not value.strip():
        return "-"
    return str(value)


def _select_snapshot_value(item: Mapping[str, Any]) -> str: # 從候選項中選擇一個代表性的snapshot值，優先使用snapshot_id，如果沒有則使用run_id，如果兩者都沒有則返回"-"
    snapshot_id = item.get("snapshot_id")
    run_id = item.get("run_id")
    if snapshot_id is not None and str(snapshot_id).strip():
        return str(snapshot_id)
    if run_id is not None and str(run_id).strip():
        return str(run_id)
    return "-"


def _normalize_candidate(item: Mapping[str, Any]) -> dict[str, Any]: # 對候選項的各個字段進行規範化處理，確保最終渲染的文本格式統一且不受原始數據中不規範格式的影響
    key_specs_raw = item.get("key_specs", {})
    key_specs = dict(key_specs_raw) if isinstance(key_specs_raw, Mapping) else {}
    return {
        "part_id": _normalize_inline_text(item.get("part_id", "-")) or "-",
        "category": _normalize_inline_text(item.get("category", "")),
        "display_name": _normalize_inline_text(item.get("display_name", "-")) or "-",
        "key_specs": key_specs,
        "price": item.get("price"),
        "source": _normalize_inline_text(item.get("source", "-")) or "-",
        "source_url": _normalize_url_text(item.get("source_url", "-")) or "-",
        "snapshot": _select_snapshot_value(item),
    }


def _ordered_categories( # 用使用者需求裡的categories控制輸出段落順序，例如：先CPU/GPU再MB/RAM，未出現在categories裡的類別會被放在最後並按字母順序排序
    compressed_by_category: Mapping[str, Sequence[CompressedCandidate]],
    category_order: Sequence[str] | None,
) -> list[str]:
    existing = {str(category): category for category in compressed_by_category.keys()}
    if category_order is None:
        return sorted(existing.keys())

    ordered: list[str] = []
    seen: set[str] = set()
    for raw in category_order:
        category = str(raw).strip()
        if not category or category in seen:
            continue
        ordered.append(category)
        seen.add(category)

    for category in sorted(existing.keys()):
        if category not in seen:
            ordered.append(category)
    return ordered


def _has_price(item: Mapping[str, Any]) -> bool: # 檢查候選項是否包含有效的價格信息，用於後續的排序邏輯，確保有價格的項目優先展示
    value = item.get("price")
    if value is None:
        return False
    if isinstance(value, str) and not value.strip():
        return False
    return True


def _rerank_items(
    items: Sequence[CompressedCandidate],
) -> list[CompressedCandidate]:
    # TODO(P3): when demand is threaded to P3, add budget-distance ranking before tie-break.
    return sorted(
        list(items),
        key=lambda item: (
            0 if _has_price(item) else 1,
            _normalize_inline_text(item.get("display_name", "")),
            _normalize_inline_text(item.get("part_id", "")),
        ),
    )


def _render_candidate_line(category: str, item: Mapping[str, Any]) -> str:
    normalized = _normalize_candidate(item)
    key_specs = normalized["key_specs"]
    spec_fragments = [
        f"{spec_key}={_normalize_spec_value(key_specs[spec_key])}"
        for spec_key in sorted(key_specs.keys())
    ]

    line_fragments = [f"[{category}#{normalized['part_id']}] {normalized['display_name']}"]
    line_fragments.extend(spec_fragments)
    line_fragments.extend(
        [
            f"price_twd={_normalize_price_value(normalized['price'])}",
            f"source={normalized['source']}",
            f"url={normalized['source_url']}",
            f"snapshot={normalized['snapshot']}",
        ]
    )
    return " | ".join(line_fragments)


def canonicalize_text_for_hash(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in normalized.split("\n")]
    body = "\n".join(lines).rstrip("\n")
    return f"{body}\n"


def hash_context_pack(text: str) -> str:
    canonicalized = canonicalize_text_for_hash(text)
    return hashlib.sha256(canonicalized.encode("utf-8")).hexdigest()


def build_context_pack(
    *,
    compressed_by_category: Mapping[str, Sequence[CompressedCandidate]],
    category_order: Sequence[str] | None = None,
    enable_rerank: bool = True,
) -> P3ContextPack:
    ordered_categories = _ordered_categories(compressed_by_category, category_order)
    sections: list[str] = []
    counts: dict[str, int] = {}

    for category in ordered_categories:
        items = list(compressed_by_category.get(category, []))
        ranked_items = _rerank_items(items) if enable_rerank else items
        counts[category] = len(ranked_items)

        section_lines = [f"=== {category} CANDIDATES ==="]
        if not ranked_items:
            section_lines.append("(no candidates)")
        else:
            for item in ranked_items:
                section_lines.append(_render_candidate_line(category, item))

        sections.append("\n".join(section_lines))

    text = canonicalize_text_for_hash("\n\n".join(sections))
    return P3ContextPack(
        text=text,
        hash=hash_context_pack(text),
        meta={
            "categories_included": ordered_categories,
            "counts": counts,
        },
    )
