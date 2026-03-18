from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.services.chat.clients.openai_compat_client import OpenAICompatError
from backend.services.chat.provider import (
    ProviderCallResult,
    ProviderDispatchError,
)
from backend.services.chat.snapshot_redaction import redact_snapshot_value

from .context import ChatPayloadContext


@dataclass(frozen=True)
class RawResponseArtifact:
    payload: dict[str, Any]
    upstream_request_id: str | None
    status_code: int | None


@dataclass(frozen=True)
class ProviderExchangePayload:
    endpoint: str
    request_headers: dict[str, Any]
    request_json: dict[str, Any]
    response_headers: dict[str, Any]
    response_json: dict[str, Any] | None
    raw_response_text: str
    upstream_request_id: str | None
    status_code: int | None


def build_provider_exchange_payload(
    *,
    model: str,
    messages: list[dict[str, str]],
    client_request_id: str,
    provider_result: ProviderCallResult | None,
    provider_error: OpenAICompatError | ProviderDispatchError | None,
) -> ProviderExchangePayload:
    default_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Client-Request-Id": client_request_id,
    }
    if provider_result is not None:
        return ProviderExchangePayload(
            endpoint=provider_result.endpoint,
            request_headers=provider_result.request_headers,
            request_json=provider_result.request_json,
            response_headers=provider_result.response_headers,
            response_json=provider_result.response_json,
            raw_response_text=provider_result.raw_response_text,
            upstream_request_id=provider_result.upstream_request_id,
            status_code=provider_result.status_code,
        )
    if provider_error is not None:
        return ProviderExchangePayload(
            endpoint=provider_error.endpoint,
            request_headers=default_headers,
            request_json=provider_error.request_json or {"model": model, "messages": messages},
            response_headers=provider_error.response_headers,
            response_json=provider_error.response_json,
            raw_response_text=provider_error.raw_response_text,
            upstream_request_id=provider_error.upstream_request_id,
            status_code=provider_error.status_code,
        )
    return ProviderExchangePayload(
        endpoint="-",
        request_headers=default_headers,
        request_json={"model": model, "messages": messages},
        response_headers={},
        response_json=None,
        raw_response_text="",
        upstream_request_id=None,
        status_code=None,
    )


def build_raw_request_payload(
    *,
    context: ChatPayloadContext,
    messages: list[dict[str, str]],
    client_request_id: str,
    provider_result: ProviderCallResult | None,
    provider_error: OpenAICompatError | ProviderDispatchError | None,
) -> dict[str, Any]:
    exchange = build_provider_exchange_payload(
        model=context.model,
        messages=messages,
        client_request_id=client_request_id,
        provider_result=provider_result,
        provider_error=provider_error,
    )
    return {
        "provider": context.provider,
        "model": context.model,
        "messages": messages,
        "context_pack_hash": context.context_pack_hash,
        "endpoint": exchange.endpoint or "-",
        "client_request_id": client_request_id,
        "request_headers": redact_snapshot_value(exchange.request_headers),
        "request_json": redact_snapshot_value(exchange.request_json),
    }


def build_raw_response_payload(
    *,
    provider_result: ProviderCallResult | None,
    provider_error: OpenAICompatError | ProviderDispatchError | None,
) -> RawResponseArtifact:
    exchange = build_provider_exchange_payload(
        model="-",
        messages=[],
        client_request_id="-",
        provider_result=provider_result,
        provider_error=provider_error,
    )
    return RawResponseArtifact(
        payload={
            "status_code": exchange.status_code,
            "response_headers": redact_snapshot_value(exchange.response_headers),
            "response_json": redact_snapshot_value(exchange.response_json),
            "raw_response_text": redact_snapshot_value(exchange.raw_response_text),
            "upstream_request_id": exchange.upstream_request_id,
        },
        upstream_request_id=exchange.upstream_request_id,
        status_code=exchange.status_code,
    )


__all__ = [
    "ProviderExchangePayload",
    "RawResponseArtifact",
    "build_provider_exchange_payload",
    "build_raw_request_payload",
    "build_raw_response_payload",
]
