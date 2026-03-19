"""Provider caller seam for chat orchestration."""

from __future__ import annotations

import re

from backend.services.chat.clients.openai_compat_client import (
    generate_openai_compat_completion,
    generate_openai_compat_text,
)
from backend.services.chat.config import (
    AISettings,
    SYSTEM_PROMPT,
    build_provider_runtime_config,
)
from backend.services.chat.contracts import ChatRequest
from backend.services.chat.prompt import build_prompt

from .models import (
    ProviderCallResult,
    ProviderCompletionGenerator,
    ProviderDispatchError,
    ProviderTextGenerator,
)
from .runtime_dispatch import (
    build_provider_config_error,
    dispatch_provider_runtime,
)

_ORIGINAL_GENERATE_OPENAI_COMPAT_TEXT = generate_openai_compat_text
_BUDGET_SIGNAL_RE = re.compile(r"(?:^|\D)\d+(?:\.\d+)?\s*(?:萬|w|k|千|元|塊)", re.IGNORECASE)
_BUILD_PATTERNS = (
    re.compile(r"配\s*單"),
    re.compile(r"配\s*置"),
    re.compile(r"組\s*(?:一?台)?\s*(?:電腦|主機|機)"),
    re.compile(r"整\s*機"),
    re.compile(r"文\s*書\s*機"),
    re.compile(r"遊\s*戲\s*機"),
    re.compile(r"工\s*作\s*站"),
    re.compile(r"推\s*薦.*(?:電腦|主機(?!板)|機)"),
)
_UPGRADE_PATTERNS = (
    re.compile(r"升\s*級"),
    re.compile(r"升級"),
    re.compile(r"換(?:掉|成)?"),
    re.compile(r"更新"),
    re.compile(r"沿用"),
    re.compile(r"保留"),
)
_CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "CPU": ("cpu", "處理器"),
    "MB": ("mb", "主機板", "motherboard"),
    "GPU": ("gpu", "顯卡", "獨顯", "rtx", "gtx", "radeon"),
    "RAM": ("ram", "記憶體"),
    "SSD": ("ssd", "固態", "nvme", "m.2"),
    "PSU": ("psu", "電供", "火牛"),
    "CASE": ("case", "機殼", "chassis"),
}


def _normalize_role(role: str) -> str:
    if role == "ai":
        return "assistant"
    return role


def _strip_internal_system_prompt(prompt: str) -> str:
    prefixed = f"{SYSTEM_PROMPT}\n\n"
    if prompt.startswith(prefixed):
        return prompt[len(prefixed) :]
    if prompt.startswith(SYSTEM_PROMPT):
        return prompt[len(SYSTEM_PROMPT) :].lstrip()
    return prompt


def _normalize_text(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _request_text(chat_request: ChatRequest) -> str:
    parts: list[str] = []
    if chat_request.user_text:
        parts.append(chat_request.user_text)
    if chat_request.messages:
        parts.extend(
            message.content
            for message in chat_request.messages
            if message.role == "user" and message.content.strip()
        )
    if chat_request.history:
        parts.extend(
            message.content
            for message in chat_request.history
            if message.role == "user" and message.content.strip()
        )
    return _normalize_text("\n".join(parts))


def _detect_requested_categories(request_text: str) -> list[str]:
    categories: list[str] = []
    for category, keywords in _CATEGORY_KEYWORDS.items():
        if any(keyword in request_text for keyword in keywords):
            categories.append(category)
    return categories


def _detect_request_shape(chat_request: ChatRequest) -> tuple[str, list[str], bool]:
    request_text = _request_text(chat_request)
    requested_categories = _detect_requested_categories(request_text)
    is_upgrade = any(pattern.search(request_text) for pattern in _UPGRADE_PATTERNS)
    is_build = any(pattern.search(request_text) for pattern in _BUILD_PATTERNS)

    if is_upgrade:
        return "upgrade", requested_categories, bool(_BUDGET_SIGNAL_RE.search(request_text))
    if is_build:
        return "build", requested_categories, bool(_BUDGET_SIGNAL_RE.search(request_text))
    if requested_categories:
        return "component", requested_categories, bool(_BUDGET_SIGNAL_RE.search(request_text))
    return "generic", [], bool(_BUDGET_SIGNAL_RE.search(request_text))


def _build_retrieval_answer_constraints(chat_request: ChatRequest) -> str:
    request_shape, requested_categories, has_budget = _detect_request_shape(chat_request)
    lines = [
        "## ANSWER_CONSTRAINTS",
        "你必須優先根據 CONTEXT_PACK 裡的候選回答。",
        "不要推薦 CONTEXT_PACK 沒出現的具體零件型號或品牌組合。",
        "如果候選不足、價格不符、或條件不清楚，請直接說資料不足並指出需要補哪些條件。",
    ]
    if has_budget:
        lines.append("若使用者有提預算，回答時必須明確說明候選是否在預算內、接近預算上限，或目前沒有符合預算的候選。")

    if request_shape == "build":
        lines.append("這是整機/配單需求：請優先用候選組合回答，不要改成通用型夢幻配單。")
    elif request_shape == "upgrade":
        lines.append("這是升級需求：請聚焦要升級的零件與相容性，不要改回整機推薦。")
    elif request_shape == "component":
        if len(requested_categories) == 1:
            lines.append(
                f"這是單零件需求：回答限制在 {requested_categories[0]} 候選，不要跳去其他零件類別。"
            )
        else:
            joined = ", ".join(requested_categories)
            lines.append(
                f"這是多零件比較需求：回答限制在 {joined} 候選，不要擴張到未要求的類別。"
            )

    return "\n".join(lines)


def _build_context_pack_message(
    chat_request: ChatRequest,
    *,
    context_pack_text: str,
) -> str:
    constraints = _build_retrieval_answer_constraints(chat_request)
    return f"{constraints}\n\n## CONTEXT_PACK\n{context_pack_text}"


def build_provider_messages(
    chat_request: ChatRequest,
    *,
    context_pack_text: str | None = None,
) -> list[dict[str, str]]:
    if chat_request.messages:
        provider_messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        provider_messages.extend(
            {"role": _normalize_role(message.role), "content": message.content}
            for message in chat_request.messages
        )
        if context_pack_text:
            provider_messages.append(
                {
                    "role": "user",
                    "content": _build_context_pack_message(
                        chat_request,
                        context_pack_text=context_pack_text,
                    ),
                }
            )
        return provider_messages

    prompt = build_prompt(
        message=chat_request.user_text or "",
        history=chat_request.history,
    )
    prompt = _strip_internal_system_prompt(prompt)
    if chat_request.demand and not isinstance(chat_request.demand, dict):
        prompt = f"{prompt}\n\n需求補充：{chat_request.demand}"
    if context_pack_text:
        prompt = (
            f"{prompt}\n\n"
            f"{_build_context_pack_message(chat_request, context_pack_text=context_pack_text)}"
        )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]


def generate_provider_result(
    *,
    settings: AISettings,
    messages: list[dict[str, str]],
    request_id: str,
    text_generator: ProviderTextGenerator | None = None,
    completion_generator: ProviderCompletionGenerator | None = None,
    original_text_generator: ProviderTextGenerator | None = None,
) -> ProviderCallResult:
    resolved_text_generator = text_generator or generate_openai_compat_text
    resolved_completion_generator = (
        completion_generator or generate_openai_compat_completion
    )
    resolved_original_text_generator = (
        original_text_generator or _ORIGINAL_GENERATE_OPENAI_COMPAT_TEXT
    )

    try:
        runtime = build_provider_runtime_config(settings)
    except ValueError as exc:
        raise build_provider_config_error(
            settings=settings,
            messages=messages,
            error=exc,
        ) from exc

    return dispatch_provider_runtime(
        runtime=runtime,
        settings=settings,
        messages=messages,
        request_id=request_id,
        text_generator=resolved_text_generator,
        completion_generator=resolved_completion_generator,
        original_text_generator=resolved_original_text_generator,
    )


__all__ = [
    "ProviderCallResult",
    "ProviderDispatchError",
    "build_provider_messages",
    "generate_provider_result",
]
