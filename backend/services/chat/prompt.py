# backend/services/chat/prompt.py
import json
from collections.abc import Mapping, Sequence
from typing import Any

from backend.schemas.chat import Turn
from backend.services.chat.config import HISTORY_MAX_TURNS, SYSTEM_PROMPT
from backend.services.chat.context_pack import CompressedPart


def build_prompt(
    message: str,
    history: list[Turn],
    compressed_candidates: dict[str, list[CompressedPart]] | None = None,
) -> str:
    def format_turn(t: Turn) -> str:
        who = "使用者" if t.role == "user" else "AI"
        return f"{who}：{t.content}"

    history_txt = "\n".join(format_turn(t) for t in history[-HISTORY_MAX_TURNS:])
    context_txt = _render_compressed_candidates(compressed_candidates or {})

    return (
        f"{SYSTEM_PROMPT}\n\n"
        f"以下是先前對話紀錄（舊→新，最多{HISTORY_MAX_TURNS}則）：\n{history_txt}\n\n"
        f"現在的使用者訊息：{message}\n"
        f"以下為候選零件資料（已做白名單壓縮）：\n{context_txt}\n"
        f"請在理解脈絡後以繁體中文回答。"
    )


def _render_compressed_candidates(candidates_by_category: Mapping[str, Sequence[Any]]) -> str:
    if not candidates_by_category:
        return "[]"

    normalized_payload: dict[str, list[dict[str, Any]]] = {}
    for category in sorted(candidates_by_category):
        normalized_items: list[dict[str, Any]] = []
        for item in candidates_by_category[category]:
            if isinstance(item, CompressedPart):
                normalized_items.append(item.model_dump(mode="json"))
                continue
            model_dump = getattr(item, "model_dump", None)
            if callable(model_dump):
                dumped = model_dump(mode="json")
                if isinstance(dumped, dict):
                    normalized_items.append(dumped)
                continue
            if isinstance(item, dict):
                normalized_items.append(dict(item))
        normalized_payload[category] = normalized_items

    return json.dumps(normalized_payload, ensure_ascii=False, sort_keys=True)
