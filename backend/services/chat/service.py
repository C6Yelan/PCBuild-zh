# backend/services/chat/service.py
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import uuid4

from pydantic import SecretBytes, SecretStr, ValidationError
from sqlalchemy.orm import Session

from backend.core.oplog import log_operation
from backend.services.chat.clients.openai_compat_client import (
    OpenAICompatError,
    OpenAICompatResult,
    generate_openai_compat_completion,
    generate_openai_compat_text,
)
from backend.services.chat.config import (
    OPENAI_COMPAT_PROVIDERS,
    AISettings,
    SYSTEM_PROMPT,
    get_ai_settings,
)
from backend.services.chat.context_pack import (
    P1Demand,
    build_context_pack,
    compress_candidates,
    retrieve_topk_candidates,
)
from backend.services.chat.contracts import ChatRequest, ChatResponse
from backend.services.chat.demand_inference import infer_chat_demand
from backend.services.chat.prompt import build_prompt

_SNAPSHOT_DIR_FALLBACK = "/tmp/pcbuild_ai_raw_snapshots"
_REDACTED = "[REDACTED]"
_ORIGINAL_GENERATE_OPENAI_COMPAT_TEXT = generate_openai_compat_text
_SENSITIVE_FIELD_NAMES = {
    "authorization",
    "api_key",
    "x_api_key",
    "x-api-key",
    "openai_api_key",
    "gemini_api_key",
    "google_api_key",
    "ai_oai_api_key",
    "ai_api_key",
}
_BEARER_TOKEN_RE = re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]+")


@dataclass(slots=True)
class _ProviderCallResult:
    text: str
    endpoint: str
    status_code: int
    request_headers: dict[str, str]
    request_json: dict[str, object]
    response_headers: dict[str, str]
    response_json: dict[str, object] | None
    raw_response_text: str
    upstream_request_id: str | None


@dataclass(slots=True)
class _ResolvedDemand:
    raw_demand: dict[str, Any] | None
    source: str


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


def _build_provider_messages(
    chat_request: ChatRequest,
    *,
    context_pack_text: str | None = None,
) -> list[dict[str, str]]:
    if chat_request.messages:
        provider_messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        provider_messages.extend(
            {"role": _normalize_role(m.role), "content": m.content}
            for m in chat_request.messages
        )
        if context_pack_text:
            provider_messages.append(
                {
                    "role": "user",
                    "content": f"## CONTEXT_PACK\n{context_pack_text}",
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
        prompt = f"{prompt}\n\n## CONTEXT_PACK\n{context_pack_text}"
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]


def _truncate_text(text: str, max_chars: int, warnings: list[str]) -> str:
    if len(text) <= max_chars:
        return text
    warnings.append("output_truncated")
    return text[:max_chars]


def _inference_inputs(chat_request: ChatRequest) -> tuple[str, list[Any]]:
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


def _resolve_effective_demand(chat_request: ChatRequest) -> _ResolvedDemand:
    if isinstance(chat_request.demand, dict):
        return _ResolvedDemand(raw_demand=chat_request.demand, source="explicit")

    message, history = _inference_inputs(chat_request)
    inferred = infer_chat_demand(message=message, history=history)
    if inferred is None:
        return _ResolvedDemand(raw_demand=None, source="none")
    return _ResolvedDemand(raw_demand=inferred, source="inferred")


def _extract_p1_inputs_from_demand(
    raw: dict[str, Any] | None,
) -> tuple[list[str], int, P1Demand | None, str]:
    if not isinstance(raw, dict):
        return [], 5, None, "prod"

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


def _is_sensitive_key(key: str | None) -> bool:
    if not key:
        return False
    lowered = key.strip().lower()
    return lowered in _SENSITIVE_FIELD_NAMES or "api_key" in lowered


def _redact_string(value: str, *, key: str | None = None) -> str:
    if _is_sensitive_key(key):
        return _REDACTED
    return _BEARER_TOKEN_RE.sub("Bearer [REDACTED]", value)


def _redact_snapshot_value(value: Any, *, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {
            str(item_key): _redact_snapshot_value(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_snapshot_value(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_snapshot_value(item) for item in value]
    if isinstance(value, str):
        return _redact_string(value, key=key)
    if _is_sensitive_key(key):
        return _REDACTED
    return value


def _write_json_file(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _write_text_file(path: Path, payload: str) -> None:
    path.write_text(payload, encoding="utf-8")


def _snapshot_root(settings: AISettings) -> Path:
    raw_dir = getattr(settings, "ai_raw_snapshot_dir", _SNAPSHOT_DIR_FALLBACK)
    normalized = str(raw_dir or _SNAPSHOT_DIR_FALLBACK).strip() or _SNAPSHOT_DIR_FALLBACK
    return Path(normalized)


def _request_mode(chat_request: ChatRequest) -> str:
    return "messages" if chat_request.messages else "user_text"


def _build_request_context_payload(
    *,
    request_id: str,
    provider: str,
    model: str,
    snapshot_id: str,
    context_pack_hash: str,
    request_mode: str,
    demand_source: str,
    triggered_retrieval: bool,
    categories: list[str],
    top_k: int,
    env: str,
    warnings: list[str],
    has_context_pack: bool,
    message_chars: int,
    history_turns: int,
) -> dict[str, Any]:
    return {
        "request_id": request_id,
        "provider": provider,
        "model": model,
        "snapshot_id": snapshot_id,
        "context_pack_hash": context_pack_hash,
        "request_mode": request_mode,
        "demand_source": demand_source,
        "triggered_retrieval": triggered_retrieval,
        "categories": categories,
        "top_k": top_k,
        "env": env,
        "warnings": list(warnings),
        "has_context_pack": has_context_pack,
        "message_chars": message_chars,
        "history_turns": history_turns,
    }


def _build_lineage_payload(
    *,
    request_id: str,
    context_pack_hash: str,
    compressed_candidates: dict[str, list[dict[str, object]]],
) -> dict[str, Any]:
    def _optional_str(value: object) -> str | None:
        if value is None:
            return None
        return str(value)

    categories: dict[str, list[dict[str, Any]]] = {}
    for category, items in compressed_candidates.items():
        category_items: list[dict[str, Any]] = []
        for item in items:
            category_items.append(
                {
                    "part_id": _optional_str(item.get("part_id")),
                    "category": _optional_str(item.get("category")) or category,
                    "display_name": _optional_str(item.get("display_name")),
                    "source": _optional_str(item.get("source")),
                    "source_url": _optional_str(item.get("source_url")),
                    "snapshot_id": _optional_str(item.get("snapshot_id")),
                    "run_id": _optional_str(item.get("run_id")),
                }
            )
        categories[category] = category_items

    return {
        "request_id": request_id,
        "context_pack_hash": context_pack_hash,
        "categories": categories,
    }


def _persist_snapshot_artifacts(
    *,
    snapshot_dir: Path,
    raw_request: dict[str, Any],
    raw_response: dict[str, Any],
    request_context: dict[str, Any],
    context_pack_text: str | None,
    compressed_candidates: dict[str, list[dict[str, object]]],
    drop_log: dict[str, dict[str, object]],
    lineage: dict[str, Any] | None,
) -> list[str]:
    artifacts: list[str] = []

    _write_json_file(snapshot_dir / "raw_request.json", raw_request)
    artifacts.append("raw_request.json")

    _write_json_file(snapshot_dir / "raw_response.json", raw_response)
    artifacts.append("raw_response.json")

    _write_json_file(snapshot_dir / "request_context.json", request_context)
    artifacts.append("request_context.json")

    if context_pack_text:
        _write_text_file(snapshot_dir / "context_pack.txt", context_pack_text)
        artifacts.append("context_pack.txt")

    if compressed_candidates:
        _write_json_file(
            snapshot_dir / "compressed_candidates.json",
            _redact_snapshot_value(compressed_candidates),
        )
        artifacts.append("compressed_candidates.json")

        _write_json_file(
            snapshot_dir / "drop_log.json",
            _redact_snapshot_value(drop_log),
        )
        artifacts.append("drop_log.json")

        if lineage is not None:
            _write_json_file(
                snapshot_dir / "lineage.json",
                _redact_snapshot_value(lineage),
            )
            artifacts.append("lineage.json")

    return artifacts


class _ProviderDispatchError(RuntimeError):
    def __init__(
        self,
        error_type: str,
        message: str,
        *,
        endpoint: str = "",
        request_json: dict[str, object] | None = None,
        response_headers: dict[str, str] | None = None,
        response_json: dict[str, object] | None = None,
        raw_response_text: str = "",
        status_code: int | None = None,
        upstream_request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.endpoint = endpoint
        self.request_json = request_json or {}
        self.response_headers = response_headers or {}
        self.response_json = response_json
        self.raw_response_text = raw_response_text
        self.status_code = status_code
        self.upstream_request_id = upstream_request_id


def _coerce_provider_result(result: OpenAICompatResult) -> _ProviderCallResult:
    return _ProviderCallResult(
        text=result.text,
        endpoint=result.endpoint,
        status_code=result.status_code,
        request_headers=result.request_headers,
        request_json=result.request_json,
        response_headers=result.response_headers,
        response_json=result.response_json,
        raw_response_text=result.raw_response_text,
        upstream_request_id=result.upstream_request_id,
    )


def _fallback_text_result(
    *,
    settings: AISettings,
    messages: list[dict[str, str]],
    request_id: str,
    text: str,
) -> _ProviderCallResult:
    request_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Client-Request-Id": request_id,
    }
    return _ProviderCallResult(
        text=text,
        endpoint=settings.ai_oai_base_url or "-",
        status_code=200,
        request_headers=request_headers,
        request_json={"model": settings.ai_model, "messages": messages},
        response_headers={},
        response_json=None,
        raw_response_text=text,
        upstream_request_id=None,
    )


def _generate_provider_result(
    *,
    settings: AISettings,
    messages: list[dict[str, str]],
    request_id: str,
) -> _ProviderCallResult:
    provider = settings.ai_provider
    if provider in OPENAI_COMPAT_PROVIDERS:
        if not settings.ai_oai_base_url:
            raise _ProviderDispatchError(
                "config_error",
                "AI_OAI_BASE_URL is required for openai-compatible providers.",
                request_json={"model": settings.ai_model, "messages": messages},
            )

        if generate_openai_compat_text is not _ORIGINAL_GENERATE_OPENAI_COMPAT_TEXT:
            text = generate_openai_compat_text(
                base_url=settings.ai_oai_base_url,
                api_key=_resolve_api_key(settings.ai_oai_api_key),
                model=settings.ai_model,
                messages=messages,
                timeout_seconds=settings.ai_timeout_seconds,
                client_request_id=request_id,
            )
            return _fallback_text_result(
                settings=settings,
                messages=messages,
                request_id=request_id,
                text=text,
            )

        result = generate_openai_compat_completion(
            base_url=settings.ai_oai_base_url,
            api_key=_resolve_api_key(settings.ai_oai_api_key),
            model=settings.ai_model,
            messages=messages,
            timeout_seconds=settings.ai_timeout_seconds,
            client_request_id=request_id,
        )
        return _coerce_provider_result(result)

    if provider == "gemini":
        raise _ProviderDispatchError(
            "provider_not_ready",
            "Gemini provider dispatch is reserved for A5 implementation.",
            request_json={"model": settings.ai_model, "messages": messages},
        )
    raise _ProviderDispatchError(
        "config_error",
        f"Unsupported AI provider: {provider}",
        request_json={"model": settings.ai_model, "messages": messages},
    )


def _write_ai_snapshot(
    *,
    settings: AISettings,
    request_id: str,
    provider: str,
    model: str,
    context_pack_hash: str,
    client_request_id: str,
    latency_ms: int,
    ok: bool,
    error_type: str | None,
    messages: list[dict[str, str]],
    request_mode: str,
    demand_source: str,
    triggered_retrieval: bool,
    categories: list[str],
    top_k: int,
    env: str,
    warnings: list[str],
    message_chars: int,
    history_turns: int,
    context_pack_text: str | None,
    compressed_candidates: dict[str, list[dict[str, object]]],
    drop_log: dict[str, dict[str, object]],
    provider_result: _ProviderCallResult | None = None,
    provider_error: OpenAICompatError | _ProviderDispatchError | None = None,
) -> str:
    snapshot_id = f"file:{request_id}"
    snapshot_dir = _snapshot_root(settings) / request_id
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    endpoint = provider_result.endpoint if provider_result else provider_error.endpoint if provider_error else "-"
    request_headers = (
        provider_result.request_headers
        if provider_result
        else {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Client-Request-Id": client_request_id,
        }
    )
    request_json = (
        provider_result.request_json
        if provider_result
        else provider_error.request_json if provider_error else {"model": model, "messages": messages}
    )
    raw_request = {
        "provider": provider,
        "model": model,
        "messages": messages,
        "context_pack_hash": context_pack_hash,
        "endpoint": endpoint or "-",
        "client_request_id": client_request_id,
        "request_headers": _redact_snapshot_value(request_headers),
        "request_json": _redact_snapshot_value(request_json),
    }

    response_headers = (
        provider_result.response_headers
        if provider_result
        else provider_error.response_headers if provider_error else {}
    )
    response_json = (
        provider_result.response_json
        if provider_result
        else provider_error.response_json if provider_error else None
    )
    raw_response_text = (
        provider_result.raw_response_text
        if provider_result
        else provider_error.raw_response_text if provider_error else ""
    )
    upstream_request_id = (
        provider_result.upstream_request_id
        if provider_result
        else provider_error.upstream_request_id if provider_error else None
    )
    status_code = (
        provider_result.status_code
        if provider_result
        else provider_error.status_code if provider_error else None
    )
    raw_response = {
        "status_code": status_code,
        "response_headers": _redact_snapshot_value(response_headers),
        "response_json": _redact_snapshot_value(response_json),
        "raw_response_text": _redact_snapshot_value(raw_response_text),
        "upstream_request_id": upstream_request_id,
    }

    request_context = _build_request_context_payload(
        request_id=request_id,
        provider=provider,
        model=model,
        snapshot_id=snapshot_id,
        context_pack_hash=context_pack_hash,
        request_mode=request_mode,
        demand_source=demand_source,
        triggered_retrieval=triggered_retrieval,
        categories=list(categories),
        top_k=top_k,
        env=env,
        warnings=warnings,
        has_context_pack=bool(context_pack_text),
        message_chars=message_chars,
        history_turns=history_turns,
    )
    lineage = (
        _build_lineage_payload(
            request_id=request_id,
            context_pack_hash=context_pack_hash,
            compressed_candidates=compressed_candidates,
        )
        if compressed_candidates
        else None
    )

    artifacts = _persist_snapshot_artifacts(
        snapshot_dir=snapshot_dir,
        raw_request=raw_request,
        raw_response=raw_response,
        request_context=request_context,
        context_pack_text=context_pack_text,
        compressed_candidates=compressed_candidates,
        drop_log=drop_log,
        lineage=lineage,
    )

    meta = {
        "request_id": request_id,
        "provider": provider,
        "model": model,
        "context_pack_hash": context_pack_hash,
        "latency_ms": latency_ms,
        "ok": ok,
        "error_type": error_type or "-",
        "snapshot_id": snapshot_id,
        "upstream_request_id": upstream_request_id,
        "status_code": status_code,
        "request_mode": request_mode,
        "demand_source": demand_source,
        "triggered_retrieval": triggered_retrieval,
        "artifacts": [*artifacts, "meta.json"],
    }

    _write_json_file(snapshot_dir / "meta.json", meta)
    return snapshot_id


def _persist_ai_snapshot(
    *,
    settings: AISettings,
    warnings: list[str],
    request_id: str,
    provider: str,
    model: str,
    context_pack_hash: str,
    latency_ms: int,
    ok: bool,
    error_type: str | None,
    messages: list[dict[str, str]],
    request_mode: str,
    demand_source: str,
    triggered_retrieval: bool,
    categories: list[str],
    top_k: int,
    env: str,
    message_chars: int,
    history_turns: int,
    context_pack_text: str | None,
    compressed_candidates: dict[str, list[dict[str, object]]],
    drop_log: dict[str, dict[str, object]],
    provider_result: _ProviderCallResult | None = None,
    provider_error: OpenAICompatError | _ProviderDispatchError | None = None,
) -> str:
    try:
        return _write_ai_snapshot(
            settings=settings,
            request_id=request_id,
            provider=provider,
            model=model,
            context_pack_hash=context_pack_hash,
            client_request_id=request_id,
            latency_ms=latency_ms,
            ok=ok,
            error_type=error_type,
            messages=messages,
            request_mode=request_mode,
            demand_source=demand_source,
            triggered_retrieval=triggered_retrieval,
            categories=categories,
            top_k=top_k,
            env=env,
            warnings=warnings,
            message_chars=message_chars,
            history_turns=history_turns,
            context_pack_text=context_pack_text,
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
            provider_result=provider_result,
            provider_error=provider_error,
        )
    except Exception as exc:
        if "ai_snapshot_write_failed" not in warnings:
            warnings.append("ai_snapshot_write_failed")
        log_operation(
            "snapshot_write_failed",
            request_id=request_id,
            provider=provider,
            model=model,
            context_pack_hash=context_pack_hash,
            error_type=type(exc).__name__,
        )
        return "-"


def _log_ai_call(
    *,
    request_id: str,
    provider: str,
    model: str,
    context_pack_hash: str,
    snapshot_id: str,
    latency_ms: int,
    ok: bool,
    error_type: str | None = None,
) -> None:
    log_operation(
        "ai_call",
        request_id=request_id,
        provider=provider,
        model=model,
        context_pack_hash=context_pack_hash,
        snapshot_id=snapshot_id,
        latency_ms=latency_ms,
        ok=ok,
        error_type=error_type or "-",
    )


def generate_chat_reply(chat_request: ChatRequest, *, db: Session | None = None) -> ChatResponse:
    settings = get_ai_settings()
    request_id = uuid4().hex
    started = perf_counter()
    warnings: list[str] = []
    compressed_candidates: dict[str, list[dict[str, object]]] = {}
    drop_log: dict[str, dict[str, object]] = {}
    context_pack_text: str | None = None
    context_pack_hash = "-"
    resolved_demand = _resolve_effective_demand(chat_request)
    categories, p1_top_k, p1_demand, p1_env = _extract_p1_inputs_from_demand(resolved_demand.raw_demand)
    message_for_inference, history_for_inference = _inference_inputs(chat_request)
    request_mode = _request_mode(chat_request)
    message_chars = len(message_for_inference)
    history_turns = len(history_for_inference)
    triggered_retrieval = db is not None and bool(categories)

    log_operation(
        "demand_resolution",
        request_id=request_id,
        source=resolved_demand.source,
        categories=",".join(categories) if categories else "-",
        top_k=p1_top_k,
        env=p1_env,
        message_chars=message_chars,
        history_turns=history_turns,
        triggered_retrieval=triggered_retrieval,
    )

    if triggered_retrieval:
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
            drop_entries = list(drop_log.values())
            fallback_count = sum(
                1
                for entry in drop_entries
                if isinstance(entry, dict)
                and isinstance(entry.get("reason"), list)
                and "fallback_used" in entry["reason"]
            )
            dropped_specs_count = sum(
                len(entry["dropped_specs"])
                for entry in drop_entries
                if isinstance(entry, dict) and isinstance(entry.get("dropped_specs"), list)
            )
            truncated_specs_count = sum(
                len(entry["truncated_specs"])
                for entry in drop_entries
                if isinstance(entry, dict) and isinstance(entry.get("truncated_specs"), dict)
            )
            log_operation(
                "p2_compress",
                env=p1_env,
                top_k=p1_top_k,
                requested_categories=",".join(categories),
                returned_categories=",".join(sorted(compressed_candidates.keys())),
                returned_count=sum(len(items) for items in compressed_candidates.values()),
                drop_log_count=len(drop_entries),
                fallback_count=fallback_count,
                dropped_specs_count=dropped_specs_count,
                truncated_specs_count=truncated_specs_count,
                max_value_len=settings.p2_max_value_len,
                max_specs_per_part=settings.p2_max_specs_per_part,
            )

            context_pack = build_context_pack(
                compressed_by_category=compressed_candidates,
                category_order=categories,
                enable_rerank=True,
                demand=p1_demand,
            )
            context_pack_text = context_pack.text
            context_pack_hash = context_pack.hash
            category_counts = ",".join(
                f"{category}:{len(compressed_candidates.get(category, []))}"
                for category in sorted(compressed_candidates.keys())
            )
            log_operation(
                "p3_context_pack",
                env=p1_env,
                context_pack_hash=context_pack_hash,
                context_pack_chars=len(context_pack.text),
                category_counts=category_counts,
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

    provider_messages = _build_provider_messages(
        chat_request,
        context_pack_text=context_pack_text,
    )

    try:
        provider_result = _generate_provider_result(
            settings=settings,
            messages=provider_messages,
            request_id=request_id,
        )
        latency_ms = int((perf_counter() - started) * 1000)
        response_text = _truncate_text(
            provider_result.text,
            max_chars=settings.ai_max_output_chars,
            warnings=warnings,
        )
        snapshot_id = _persist_ai_snapshot(
            settings=settings,
            warnings=warnings,
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            context_pack_hash=context_pack_hash,
            latency_ms=latency_ms,
            ok=True,
            error_type="-",
            messages=provider_messages,
            request_mode=request_mode,
            demand_source=resolved_demand.source,
            triggered_retrieval=triggered_retrieval,
            categories=categories,
            top_k=p1_top_k,
            env=p1_env,
            message_chars=message_chars,
            history_turns=history_turns,
            context_pack_text=context_pack_text,
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
            provider_result=provider_result,
        )
        _log_ai_call(
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            context_pack_hash=context_pack_hash,
            snapshot_id=snapshot_id,
            latency_ms=latency_ms,
            ok=True,
            error_type="-",
        )
        return ChatResponse(
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            text=response_text,
            latency_ms=latency_ms,
            warnings=warnings or None,
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
        )
    except OpenAICompatError as exc:
        latency_ms = int((perf_counter() - started) * 1000)
        snapshot_id = _persist_ai_snapshot(
            settings=settings,
            warnings=warnings,
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            context_pack_hash=context_pack_hash,
            latency_ms=latency_ms,
            ok=False,
            error_type=exc.error_type,
            messages=provider_messages,
            request_mode=request_mode,
            demand_source=resolved_demand.source,
            triggered_retrieval=triggered_retrieval,
            categories=categories,
            top_k=p1_top_k,
            env=p1_env,
            message_chars=message_chars,
            history_turns=history_turns,
            context_pack_text=context_pack_text,
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
            provider_error=exc,
        )
        _log_ai_call(
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            context_pack_hash=context_pack_hash,
            snapshot_id=snapshot_id,
            latency_ms=latency_ms,
            ok=False,
            error_type=exc.error_type,
        )
        return ChatResponse(
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            text="目前 AI 服務暫時不可用，請稍後再試。",
            latency_ms=latency_ms,
            error_type=exc.error_type,
            warnings=warnings or None,
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
        )
    except _ProviderDispatchError as exc:
        latency_ms = int((perf_counter() - started) * 1000)
        snapshot_id = _persist_ai_snapshot(
            settings=settings,
            warnings=warnings,
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            context_pack_hash=context_pack_hash,
            latency_ms=latency_ms,
            ok=False,
            error_type=exc.error_type,
            messages=provider_messages,
            request_mode=request_mode,
            demand_source=resolved_demand.source,
            triggered_retrieval=triggered_retrieval,
            categories=categories,
            top_k=p1_top_k,
            env=p1_env,
            message_chars=message_chars,
            history_turns=history_turns,
            context_pack_text=context_pack_text,
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
            provider_error=exc,
        )
        _log_ai_call(
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            context_pack_hash=context_pack_hash,
            snapshot_id=snapshot_id,
            latency_ms=latency_ms,
            ok=False,
            error_type=exc.error_type,
        )
        return ChatResponse(
            request_id=request_id,
            provider=settings.ai_provider,
            model=settings.ai_model,
            text="目前 AI 服務提供者尚未啟用，請稍後再試。",
            latency_ms=latency_ms,
            error_type=exc.error_type,
            warnings=warnings or None,
            compressed_candidates=compressed_candidates,
            drop_log=drop_log,
        )
