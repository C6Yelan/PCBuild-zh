"""Provider caller seam for chat orchestration."""

from __future__ import annotations

import json

from backend.services.chat.clients.openai_compat_client import (
    generate_openai_compat_completion,
    generate_openai_compat_text,
)
from backend.services.chat.build_policy import BuildRequestProfile
from backend.services.chat.build_scoring import build_scoring_message
from backend.services.chat.config import (
    AISettings,
    SYSTEM_PROMPT,
    build_provider_runtime_config,
)
from backend.services.chat.contracts import ChatRequest, NormalizedDemand
from backend.services.chat.prompt import build_prompt
from backend.services.chat.service.normalization import rule_fallback_normalized_demand

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


def _message_text_for_normalization(chat_request: ChatRequest) -> tuple[str, list[object]]:
    if chat_request.user_text:
        return chat_request.user_text, list(chat_request.history)

    if not chat_request.messages:
        return "", []

    last_user_index: int | None = None
    for index in range(len(chat_request.messages) - 1, -1, -1):
        if chat_request.messages[index].role == "user":
            last_user_index = index
            break
    if last_user_index is None:
        return "", list(chat_request.messages)
    return (
        chat_request.messages[last_user_index].content,
        list(chat_request.messages[:last_user_index]),
    )


def _build_retrieval_answer_constraints(
    normalized_demand: NormalizedDemand,
    *,
    build_profile: BuildRequestProfile | None,
    context_pack_meta: dict[str, object] | None,
) -> str:
    requested_categories = list(normalized_demand.categories)
    category_counts = dict((context_pack_meta or {}).get("counts", {}))
    lines = [
        "## ANSWER_CONSTRAINTS",
        "你只能根據 CLEAN_CONTEXT_PACK 裡存在的候選作答。",
        "不可推薦 CLEAN_CONTEXT_PACK 以外的零件、品牌組合或規格。",
        "若候選不足、價格不符、或資料不完整，必須直接說資料不足或候選不足，不可硬湊。",
        "先給結論，再給理由；全部使用繁體中文。",
    ]
    if normalized_demand.budget_max is not None or normalized_demand.budget_target is not None:
        lines.append("若有預算，必須明確說明候選是否接近預算或目前沒有符合預算的候選。")

    if normalized_demand.request_mode == "build":
        lines.append("這是整機 build 需求：優先維持需求一致性與相容性，不可改成單品問答。")
        lines.append("回答格式至少要有：1. 一句結論判斷這組 gaming build 是否合理。2. 零件清單。3. 說明 CPU/GPU/MB/RAM 的平衡。4. 若有候選不足或取捨，直接說。")
    elif normalized_demand.request_mode == "upgrade":
        lines.append("這是升級需求：聚焦升級目標與相容性，不可改回整機夢幻單。")
        lines.append("若有 build scoring，必須優先參考其 selected_build 與 warning，不可只因為相容就把失衡組合寫成首選。")
    elif normalized_demand.request_mode == "single_part":
        if len(requested_categories) == 1:
            lines.append(f"這是單品需求：回答限制在 {requested_categories[0]} 候選，不可轉成整機 build。")
        elif requested_categories:
            lines.append(f"這是多單品需求：回答限制在 {', '.join(requested_categories)} 候選。")

    if "GPU" in requested_categories and not normalized_demand.allow_workstation_gpu:
        lines.append("若使用者問的是遊戲顯卡或一般顯卡單品，預設不可把 workstation/pro 卡當主推薦。")
    if build_profile is not None and build_profile.minimum_budget_utilization is not None:
        lines.append(
            f"若 build 清單總價明顯低於 {build_profile.minimum_budget_utilization}，必須保守說明候選不足或條件過嚴。"
        )
    if normalized_demand.missing_information:
        lines.append(
            f"若需要更精準建議，可明確指出目前仍缺少：{', '.join(normalized_demand.missing_information)}。"
        )
    if requested_categories:
        joined = ", ".join(f"{category}:{category_counts.get(category, 0)}" for category in requested_categories)
        lines.append(f"目前 clean candidate counts：{joined}。")

    return "\n".join(lines)


def _build_context_pack_message(
    *,
    normalized_demand: NormalizedDemand,
    build_profile: BuildRequestProfile | None,
    context_pack_meta: dict[str, object] | None,
    context_pack_text: str,
) -> str:
    constraints = _build_retrieval_answer_constraints(
        normalized_demand,
        build_profile=build_profile,
        context_pack_meta=context_pack_meta,
    )
    normalized_payload = json.dumps(
        normalized_demand.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    )
    build_scoring_payload = build_scoring_message((context_pack_meta or {}).get("build_scoring"))
    build_scoring_block = ""
    if build_scoring_payload:
        build_scoring_block = f"\n\n## BUILD_SCORING\n{build_scoring_payload}"
    return (
        f"{constraints}\n\n"
        f"## NORMALIZED_DEMAND\n{normalized_payload}\n\n"
        f"## CONTEXT_PACK\nclean_context_pack=true\n{context_pack_text}"
        f"{build_scoring_block}"
    )


def build_provider_messages(
    chat_request: ChatRequest,
    *,
    context_pack_text: str | None = None,
    context_pack_meta: dict[str, object] | None = None,
    normalized_demand: NormalizedDemand | None = None,
    build_profile: BuildRequestProfile | None = None,
) -> list[dict[str, str]]:
    if normalized_demand is None:
        message_text, history = _message_text_for_normalization(chat_request)
        resolved_normalized_demand = rule_fallback_normalized_demand(
            message_text=message_text,
            history=history,
        )
    else:
        resolved_normalized_demand = normalized_demand
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
                        normalized_demand=resolved_normalized_demand,
                        build_profile=build_profile,
                        context_pack_meta=context_pack_meta,
                        context_pack_text=context_pack_text,
                    ),
                }
            )
        else:
            provider_messages.append(
                {
                    "role": "user",
                    "content": "## NORMALIZED_DEMAND\n"
                    + json.dumps(
                        resolved_normalized_demand.model_dump(mode="json"),
                        ensure_ascii=False,
                        sort_keys=True,
                        indent=2,
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
            f"{_build_context_pack_message(normalized_demand=resolved_normalized_demand, build_profile=build_profile, context_pack_meta=context_pack_meta, context_pack_text=context_pack_text)}"
        )
    else:
        prompt = (
            f"{prompt}\n\n## NORMALIZED_DEMAND\n"
            f"{json.dumps(resolved_normalized_demand.model_dump(mode='json'), ensure_ascii=False, sort_keys=True, indent=2)}"
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
    extra_payload: dict[str, object] | None = None,
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
        extra_payload=extra_payload,
    )


__all__ = [
    "ProviderCallResult",
    "ProviderDispatchError",
    "build_provider_messages",
    "generate_provider_result",
]
