# backend/services/email/client.py
from __future__ import annotations

from functools import lru_cache
from typing import Iterable, Sequence

import resend
from pydantic import BaseModel, EmailStr, ValidationError

from .config import get_resend_settings
from .templates import (
    build_signup_verification_email,
    build_password_reset_email,
)


class EmailRecipient(BaseModel):
    """收件人結構，未來若要擴充姓名欄位比較容易。"""
    email: EmailStr


class EmailMessage(BaseModel):
    """寄信請求物件，統一進入點，方便之後做 logging / queue 等擴充。"""
    to: Sequence[EmailRecipient]
    subject: str
    html: str
    cc: Sequence[EmailRecipient] | None = None
    bcc: Sequence[EmailRecipient] | None = None
    reply_to: EmailStr | None = None


class ResendEmailClient:
    """封裝 Resend SDK。

    之後若要支援多個 provider，可以用同樣介面換掉底層實作。
    """

    def __init__(self) -> None:
        settings = get_resend_settings()
        # 集中設定 api_key，之後透過單例重複使用
        resend.api_key = settings.api_key
        self._from_header = settings.from_header

    def send_email(self, message: EmailMessage) -> str:
        """送出 Email，回傳 Resend 產生的 email id。

        若 Resend 回應錯誤，會直接拋出例外，交由上層 FastAPI handler 統一處理。
        """
        to_list = [r.email for r in message.to]
        cc_list = [r.email for r in (message.cc or [])] or None
        bcc_list = [r.email for r in (message.bcc or [])] or None

        payload: dict = {
            "from": self._from_header,
            "to": to_list,
            "subject": message.subject,
            "html": message.html,
        }
        if cc_list:
            payload["cc"] = cc_list
        if bcc_list:
            payload["bcc"] = bcc_list
        if message.reply_to:
            payload["reply_to"] = message.reply_to

        # 官方建議的呼叫方式：resend.Emails.send(...)
        result = resend.Emails.send(payload)

        # 嘗試從 SDK 回傳物件取得 id（視版本可能是屬性或 dict）
        email_id = getattr(result, "id", None)
        if email_id is None and isinstance(result, dict):
            email_id = result.get("id")

        if not email_id:
            # 不在 log 中印出 payload，避免洩漏收件人資料
            raise RuntimeError("Resend did not return an email id.")

        return str(email_id)


# === 單例(Singleton) client：集中建立、全程重用 ===

@lru_cache
def get_email_client() -> ResendEmailClient:
    """回傳單一 ResendEmailClient 實例（process 級別的 singleton）。"""
    return ResendEmailClient()


# === 集中入口函式 ===

def send_email(message: EmailMessage) -> str:
    """集中寄信入口，統一經由單例 client，未來可在這裡加 logging / queue。"""
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
    """提供一個安全的建構函式，避免在各處手動 new EmailMessage 時重複轉型。"""
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
        # 保留 ValidationError 讓上層看得到是哪個 email 格式錯誤
        raise exc


# === 註冊驗證信：使用集中入口 ===
def send_signup_verification_email(to_email: str, verify_url: str) -> str:
    """
    註冊流程專用的驗證信寄送。

    未來登入驗證可以另外實作 send_login_verification_email，
    但仍然呼叫同一個 send_email() 作為集中入口。
    """
    subject, html = build_signup_verification_email(verify_url)

    message = build_email_message(
        to=[to_email],
        subject=subject,
        html=html,
    )

    return send_email(message)

#== 忘記密碼信：使用集中入口 ===
def send_password_reset_email(to_email: str, reset_url: str) -> str:
    """
    忘記密碼流程專用的重設密碼信寄送。

    - 不處理帳號是否存在 / 是否啟用的判斷，這些在上層 service 做
    - 這裡只負責套用重設密碼樣板並透過集中入口 send_email() 寄出
    """
    subject, html = build_password_reset_email(reset_url)

    message = build_email_message(
        to=[to_email],
        subject=subject,
        html=html,
    )

    return send_email(message)
