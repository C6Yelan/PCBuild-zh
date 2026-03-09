# backend/services/chat/retry_policy.py
from __future__ import annotations


MAX_CHAT_ATTEMPTS = 2
RETRYABLE_CHAT_ERROR_TYPES = {"timeout", "429", "network_error"}
RETRY_BACKOFF_SECONDS = 0.2


def should_retry_chat_error(error_type: str, *, attempt: int) -> bool:
    return attempt < MAX_CHAT_ATTEMPTS and error_type in RETRYABLE_CHAT_ERROR_TYPES

