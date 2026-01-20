# backend/services/auth/tokens/email_tokens_issue.py
from __future__ import annotations

import secrets
from datetime import timedelta

from sqlalchemy.orm import Session

from backend.models import User, EmailVerificationToken
from backend.services.auth.verification.core import (
    VerificationPurpose,
    RESEND_MIN_INTERVAL_MINUTES,
    VerificationEmailRateLimitedError,
    utcnow,
    hash_token,
    resolve_lifetime_minutes,
    get_latest_token_for_user,
)
from backend.core.seclog import log_security


def issue_verification_token(
    db: Session,
    user: User,
    *,
    purpose: VerificationPurpose,
    expires_in_minutes: int | None = None,
) -> str:
    """
    發行驗證碼（通用版本）。
    回傳 public token 格式為 "<id>.<secret>"
    """
    lifetime_minutes = resolve_lifetime_minutes(purpose, expires_in_minutes)

    secret = secrets.token_urlsafe(32)
    token_hash = hash_token(secret)
    now = utcnow()
    expires_at = now + timedelta(minutes=lifetime_minutes)

    token = EmailVerificationToken(
        user_id=user.id,
        token_hash=token_hash,
        purpose=purpose.value,
        is_used=False,
        created_at=now,
        expires_at=expires_at,
    )
    db.add(token)
    db.commit()
    db.refresh(token)
    log_security(
        "verification_token_issued",
        user_id=user.id,
        purpose=purpose.value,
        token_id=token.id,
        expires_in_minutes=lifetime_minutes,
    )

    return f"{token.id}.{secret}"


def issue_password_reset_token_for_user(
    db: Session,
    user: User,
    *,
    min_interval_minutes: int | None = None,
) -> str:
    """
    忘記密碼流程專用：為指定使用者發行「重設密碼」 token。
    - 依 PASSWORD_RESET 冷卻時間做簡單 rate limit
    """
    now = utcnow()

    if min_interval_minutes is None:
        min_interval_minutes = RESEND_MIN_INTERVAL_MINUTES[
            VerificationPurpose.PASSWORD_RESET
        ]

    latest = get_latest_token_for_user(
        db=db,
        user_id=user.id,
        purpose=VerificationPurpose.PASSWORD_RESET,
    )
    if latest is not None and latest.created_at + timedelta(minutes=min_interval_minutes) > now:
        retry_after_sec = int(
            (latest.created_at + timedelta(minutes=min_interval_minutes) - now).total_seconds()
        )
        log_security(
            "password_reset_rate_limited",
            user_id=user.id,
            purpose=VerificationPurpose.PASSWORD_RESET.value,
            retry_after_sec=retry_after_sec,
        )
        raise VerificationEmailRateLimitedError("重設密碼請求太頻繁，請稍後再試。")

    return issue_verification_token(
        db=db,
        user=user,
        purpose=VerificationPurpose.PASSWORD_RESET,
    )
