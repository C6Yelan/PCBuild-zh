# backend/services/chat/clients/openai_compat_client.py
from __future__ import annotations

from urllib.parse import urljoin

import httpx
from pydantic import SecretStr


class OpenAICompatError(RuntimeError):
    def __init__(self, error_type: str, message: str = "") -> None:
        super().__init__(message or error_type)
        self.error_type = error_type


def generate_openai_compat_text(
    *,
    base_url: str,
    api_key: SecretStr | str | None,
    model: str,
    messages: list[dict[str, str]],
    timeout_seconds: float,
) -> str:
    endpoint = urljoin(f"{base_url.rstrip('/')}/", "chat/completions")
    headers: dict[str, str] = {"Content-Type": "application/json"}
    resolved_api_key = (
        api_key.get_secret_value() if isinstance(api_key, SecretStr) else api_key
    )
    if resolved_api_key:
        headers["Authorization"] = f"Bearer {resolved_api_key}"

    payload = {
        "model": model,
        "messages": messages,
    }

    try:
        response = httpx.post(
            endpoint,
            headers=headers,
            json=payload,
            timeout=timeout_seconds,
        )
    except httpx.TimeoutException as exc:
        raise OpenAICompatError("timeout") from exc
    except httpx.RequestError as exc:
        raise OpenAICompatError("network_error") from exc

    if response.status_code == 429:
        raise OpenAICompatError("rate_limited_429")
    if response.status_code >= 500:
        raise OpenAICompatError("upstream_5xx")
    if response.status_code >= 400:
        raise OpenAICompatError("network_error")

    try:
        data = response.json()
    except ValueError as exc:
        raise OpenAICompatError("invalid_response") from exc

    try:
        choice = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise OpenAICompatError("invalid_response") from exc

    if isinstance(choice, str):
        return choice.strip()
    raise OpenAICompatError("invalid_response")
