# backend/api/routes/auth/password/forgot_password.py
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session as OrmSession

from backend.api.dependencies.db import get_db
from backend.api.auth.config import RESEND_PASSWORD_RESET_MIN_INTERVAL_SECONDS
from backend.api.routes.auth._shared.email_action_guards import (
    find_user_by_email,
    log_email_action_security_event,
    raise_email_action_cooldown,
    validate_email_action_email,
)
from backend.schemas.auth import ForgotPasswordIn
from backend.services.auth.workflows.password_reset import send_password_reset_for_user
from backend.services.auth.verification.core import (
    VerificationEmailRateLimitedError,
    VerificationPurpose,
)
from backend.core.middleware.throttling.rate_limit import limiter

router = APIRouter()


# ===== 忘記密碼：發送重設密碼信 =====
@router.post("/forgot-password")
@limiter.shared_limit("10/minute", scope="email_actions")
def forgot_password(
    body: ForgotPasswordIn,
    request: Request,
    response: Response, # <- 新增這行（符合 SlowAPI headers_enabled=True 的要求）
    db: OrmSession = Depends(get_db),
):
    """
    忘記密碼入口：

    - 一律回傳 200 + {"ok": True}（不暴露帳號是否存在 / 是否已啟用）
    - 若 email 格式錯誤，回 400 提示使用者修正
    - 若帳號存在，才實際發 PASSWORD_RESET token 並寄信
    - 若請求過於頻繁，回 429 告知稍後再試
    """
    validate_email_action_email(
        request,
        email=body.email,
        endpoint="forgot_password",
    )

    user = find_user_by_email(db, email=body.email)
    if not user:
        log_email_action_security_event(
            request,
            event="password_reset_request_unknown",
            email=body.email,
        )
        return {"ok": True}

    try:
        send_password_reset_for_user(db=db, user=user, request=request)
    except VerificationEmailRateLimitedError:
        raise_email_action_cooldown(
            request,
            db=db,
            user=user,
            purpose=VerificationPurpose.PASSWORD_RESET,
            cooldown_seconds=RESEND_PASSWORD_RESET_MIN_INTERVAL_SECONDS,
            event="password_reset_rate_limited",
            message="重設密碼請求太頻繁，請稍後再試。",
            user_id=user.id,
        )

    log_email_action_security_event(
        request,
        event="password_reset_email_sent",
        user_id=user.id,
    )
    return {"ok": True}
