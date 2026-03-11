# backend/api/routes/auth/password/forgot_password.py
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session as OrmSession

from backend.api.dependencies.db import get_db
from backend.api.auth.config import EMAIL_ADAPTER, RESEND_PASSWORD_RESET_MIN_INTERVAL_SECONDS
from backend.api.auth.utils import raise_400
from backend.api.routes.auth._shared.email_action_guards import (
    build_email_action_log_fields,
    build_rate_limited_exception,
    compute_retry_after_seconds,
)
from backend.models import User
from backend.schemas.auth import ForgotPasswordIn
from backend.services.auth.workflows.password_reset import send_password_reset_for_user
from backend.services.auth.verification.core import (
    VerificationEmailRateLimitedError,
    VerificationPurpose,
)
from backend.core.middleware.throttling.rate_limit import limiter
from backend.core.seclog import log_security

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
    try:
        EMAIL_ADAPTER.validate_python(body.email)
    except Exception:
        log_security(
            "authn_input_invalid",
            reason="email_format",
            **build_email_action_log_fields(request, endpoint="forgot_password"),
        )
        raise_400({"email": "Email 格式不正確。"})

    user = db.query(User).filter(User.email == body.email).first()
    if not user:
        log_security(
            "password_reset_request_unknown",
            **build_email_action_log_fields(request, email=body.email),
        )
        return {"ok": True}

    try:
        send_password_reset_for_user(db=db, user=user, request=request)
    except VerificationEmailRateLimitedError:
        retry_after = compute_retry_after_seconds(
            db,
            user=user,
            purpose=VerificationPurpose.PASSWORD_RESET,
            cooldown_seconds=RESEND_PASSWORD_RESET_MIN_INTERVAL_SECONDS,
        )

        log_security(
            "password_reset_rate_limited",
            **build_email_action_log_fields(request, user_id=user.id, retry_after=retry_after),
        )

        raise build_rate_limited_exception(
            message="重設密碼請求太頻繁，請稍後再試。",
            retry_after=retry_after,
        )

    log_security(
        "password_reset_email_sent",
        **build_email_action_log_fields(request, user_id=user.id),
    )
    return {"ok": True}
