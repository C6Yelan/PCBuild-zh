"""Compatibility shim for provider runtime dispatch helpers."""

from __future__ import annotations

from backend.services.chat.provider.runtime_dispatch import (
    build_provider_config_error,
    build_unsupported_provider_error,
    coerce_provider_result,
    dispatch_provider_runtime,
    fallback_text_result,
)

__all__ = [
    "build_provider_config_error",
    "build_unsupported_provider_error",
    "coerce_provider_result",
    "dispatch_provider_runtime",
    "fallback_text_result",
]
