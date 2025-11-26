# backend/services/email/config.py
from __future__ import annotations

import os
from pydantic import BaseModel, EmailStr


class ResendSettings(BaseModel):
    """Resend 相關設定，從環境變數載入。"""
    api_key: str
    from_email: EmailStr
    from_name: str = "PCBuild"
    region: str | None = None

    @property
    def from_header(self) -> str:
        """產生 'Name <email@example.com>' 格式的寄件人字串。"""
        return f"{self.from_name} <{self.from_email}>"


def get_resend_settings() -> ResendSettings:
    """從環境變數組出 Resend 設定，若必要參數缺少就直接拋出錯誤。"""
    api_key = os.getenv("RESEND_API_KEY")
    from_email = os.getenv("RESEND_FROM_EMAIL")
    from_name = os.getenv("RESEND_FROM_NAME", "PCBuild")
    region = os.getenv("RESEND_REGION")

    if not api_key:
        raise RuntimeError("RESEND_API_KEY is not set in environment variables.")

    if not from_email:
        raise RuntimeError("RESEND_FROM_EMAIL is not set in environment variables.")

    return ResendSettings(
        api_key=api_key,
        from_email=from_email,
        from_name=from_name,
        region=region,
    )
