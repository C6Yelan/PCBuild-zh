"""Stable provider caller compatibility shim."""

from __future__ import annotations

from backend.services.chat.provider import (
    ProviderCallResult,
    ProviderDispatchError,
    build_provider_messages,
    generate_provider_result,
)

__all__ = [
    "ProviderCallResult",
    "ProviderDispatchError",
    "build_provider_messages",
    "generate_provider_result",
]
