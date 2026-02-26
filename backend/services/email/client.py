# backend/services/email/client.py
from __future__ import annotations

from .service import (
    build_email_message,
    get_email_client,
    send_email,
    send_password_changed_email,
    send_password_reset_email,
    send_signup_verification_email,
)
from .types import EmailMessage, EmailRecipient

__all__ = [
    "EmailRecipient",
    "EmailMessage",
    "get_email_client",
    "send_email",
    "build_email_message",
    "send_signup_verification_email",
    "send_password_reset_email",
    "send_password_changed_email",
]
