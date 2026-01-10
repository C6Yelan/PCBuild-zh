# backend/api/auth_config.py
import os
from pydantic import EmailStr, TypeAdapter

EMAIL_ADAPTER = TypeAdapter(EmailStr)

SESSION_COOKIE_NAME = "pcbuild_session"
SESSION_EXPIRES_MINUTES = int(os.getenv("SESSION_EXPIRES_MINUTES", "120"))
RESEND_MIN_INTERVAL_SECONDS = 60  # 與前端倒數一致（1 分鐘）
