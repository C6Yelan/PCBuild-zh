# backend/services/email/service.py
from __future__ import annotations

from functools import lru_cache
from typing import Iterable

from pydantic import ValidationError

from .resend_client import ResendEmailClient
from .templates import (
    build_password_changed_email,
    build_password_reset_email,
    build_signup_verification_email,
)
from .types import EmailMessage, EmailRecipient


@lru_cache
def get_email_client() -> ResendEmailClient:
    """回傳單一 ResendEmailClient 實例（process 級別 singleton）。"""
    return ResendEmailClient()


def send_email(message: EmailMessage) -> str:
    """集中寄信入口，統一經由單例 client。"""
    client = get_email_client()
    return client.send_email(message)


def build_email_message(
    to: Iterable[str],
    subject: str,
    html: str,
    *,
    cc: Iterable[str] | None = None,
    bcc: Iterable[str] | None = None,
    reply_to: str | None = None,
) -> EmailMessage:
    """安全建構 EmailMessage，避免各處重複轉型。"""
    try:
        return EmailMessage(
            to=[EmailRecipient(email=addr) for addr in to],
            subject=subject,
            html=html,
            cc=[EmailRecipient(email=addr) for addr in (cc or [])] or None,
            bcc=[EmailRecipient(email=addr) for addr in (bcc or [])] or None,
            reply_to=reply_to,
        )
    except ValidationError as exc:
        # 保留 ValidationError，讓上層能取得錯誤細節
        raise exc


def send_signup_verification_email(to_email: str, verify_url: str) -> str:
    """註冊驗證信寄送（僅負責套模板 + 寄送）。"""
    subject, html = build_signup_verification_email(verify_url)
    message = build_email_message(to=[to_email], subject=subject, html=html)
    return send_email(message)


def send_password_reset_email(to_email: str, reset_url: str) -> str:
    """忘記密碼信寄送（僅負責套模板 + 寄送）。"""
    subject, html = build_password_reset_email(reset_url)
    message = build_email_message(to=[to_email], subject=subject, html=html)
    return send_email(message)


def send_password_changed_email(to_email: str) -> str:
    """密碼已修改通知信寄送（僅負責套模板 + 寄送）。"""
    subject, html = build_password_changed_email()
    message = build_email_message(to=[to_email], subject=subject, html=html)
    return send_email(message)
