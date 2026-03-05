# backend/services/chat/service.py
from __future__ import annotations

from time import perf_counter
from uuid import uuid4

from pydantic import SecretBytes, SecretStr, ValidationError
from sqlalchemy.orm import Session

from backend.core.oplog import log_operation
from backend.services.chat.clients import OpenAICompatError, generate_openai_compat_text
from backend.services.chat.config import get_ai_settings
from backend.services.chat.context_pack import P1Demand, compress_candidates, retrieve_topk_candidates
from backend.services.chat.contracts import ChatRequest, ChatResponse
from backend.services.chat.prompt import build_prompt


def _normalize_role(role: str) -> str:
    if role == "ai":
        return "assistant"
    return role


def _build_provider_messages(chat_request: ChatRequest) -> list[dict[str, str]]:
    if chat_request.messages:
        return [
            {"role": _normalize_role(m.role), "content": m.content}
            for m in chat_request.messages
        ]

    prompt = build_prompt(
        message=chat_request.user_text or "",
        history=chat_request.history,
    )
    if chat_request.demand and not isinstance(chat_request.demand, dict):
        prompt = f"{prompt}\n\n需求補充：{chat_request.demand}"
    return [{"role": "user", "content": prompt}]


def _truncate_text(text: str, max_chars: int, warnings: list[str]) -> str:
    if len(text) <= max_chars:
        return text
    warnings.append("output_truncated")
    return text[:max_chars]


def _extract_p1_inputs(chat_request: ChatRequest) -> tuple[list[str], int, P1Demand | None, str]:
    if not isinstance(chat_request.demand, dict):
        return [], 5, None, "prod"

    raw = chat_request.demand

    categories: list[str] = []
    raw_categories = raw.get("categories")
    if isinstance(raw_categories, list):
        for value in raw_categories:
            normalized = str(value).strip()
            if normalized:
                categories.append(normalized)

    raw_top_k = raw.get("top_k", 5)
    try:
        top_k = int(raw_top_k)
    except (TypeError, ValueError):
        top_k = 5

    raw_env = raw.get("env")
    env = raw_env.strip() if isinstance(raw_env, str) and raw_env.strip() else "prod"

    p1_demand: P1Demand | None = None
    raw_filters = raw.get("filters")
    if isinstance(raw_filters, dict):
        try:
            p1_demand = P1Demand.model_validate(raw_filters)
        except ValidationError:
            p1_demand = None

    return categories, top_k, p1_demand, env


def _resolve_api_key(api_key: SecretStr | SecretBytes | str | None) -> str | None:
    if isinstance(api_key, SecretStr):
        return api_key.get_secret_value()
    if isinstance(api_key, SecretBytes):
        value = api_key.get_secret_value()
        return value.decode("utf-8", errors="ignore")
    if isinstance(api_key, str):
        return api_key
    return None


def generate_chat_reply(chat_request: ChatRequest, *, db: Session | None = None) -> ChatResponse:
    settings = get_ai_settings()
    request_id = uuid4().hex
    started = perf_counter()
    warnings: list[str] = []
    compressed_candidates: dict[str, list[dict[str, object]]] = {}
    drop_log: dict[str, dict[str, object]] = {}

    if db is not None:
        categories, p1_top_k, p1_demand, p1_env = _extract_p1_inputs(chat_request)
        if categories:
            try:
                p1_result = retrieve_topk_candidates(
                    db,
                    categories=categories,
                    top_k=p1_top_k,
                    demand=p1_demand,
                    env=p1_env,
                )
                compressed_candidates, drop_log = compress_candidates(
                    p1_result,
                    spec_whitelist_by_category=settings.p2_spec_whitelist_by_category,
                    max_value_len=settings.p2_max_value_len,
                    max_specs_per_part=settings.p2_max_specs_per_part,
                )
            except Exception as exc:
                warnings.append("p1_retrieval_failed")
                log_operation(
                    "p1_retrieval_failed",
                    error_type=type(exc).__name__,
                    env=p1_env,
                    categories=",".join(categories),
                    top_k=p1_top_k,
                )
                compressed_candidates = {}
                drop_log = {}

    try:
        response_text = generate_openai_compat_text(
            base_url=settings.ai_oai_base_url,
            api_key=_resolve_api_key(settings.ai_oai_api_key),
            model=settings.ai_model,
            messages=_build_provider_messages(chat_request),
            timeout_seconds=settings.ai_timeout_seconds,
        )
        response_text = _truncate_text(
            response_text,
            max_chars=settings.ai_max_output_chars,
            warnings=warnings,
        )
        return ChatResponse(
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            text=response_text,
            latency_ms=int((perf_counter() - started) * 1000),
            warnings=warnings or None,
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
        )
    except OpenAICompatError as exc:
        return ChatResponse(
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            text="目前 AI 服務暫時不可用，請稍後再試。",
            latency_ms=int((perf_counter() - started) * 1000),
            error_type=exc.error_type,
            warnings=warnings or None,
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
        )
