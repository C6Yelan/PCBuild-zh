# backend/api/routes/auth/password/forgot_password.py
import math
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session as OrmSession

from backend.api.dependencies.db import get_db
from backend.api.auth.config import EMAIL_ADAPTER, RESEND_PASSWORD_RESET_MIN_INTERVAL_SECONDS
from backend.api.auth.utils import raise_400
from backend.models import User, EmailVerificationToken
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
            endpoint="forgot_password",
            client=(request.headers.get("cf-connecting-ip")
                    or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                    or getattr(request.client, "host", "-")),
            method=request.method,
            path=request.url.path,
        )
        raise_400({"email": "Email 格式不正確。"})

    user = db.query(User).filter(User.email == body.email).first()
    if not user:
        email_domain = body.email.split("@", 1)[-1].lower() if "@" in body.email else "-"
        log_security(
            "password_reset_request_unknown",
            email_domain=email_domain,
            client=(request.headers.get("cf-connecting-ip")
                    or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                    or getattr(request.client, "host", "-")),
            method=request.method,
            path=request.url.path,
        )
        return {"ok": True}

    try:
        send_password_reset_for_user(db=db, user=user, request=request)
    except VerificationEmailRateLimitedError:
        now = datetime.now(timezone.utc)
        latest = (
            db.query(EmailVerificationToken)
            .filter(
                EmailVerificationToken.user_id == user.id,
                EmailVerificationToken.purpose == VerificationPurpose.PASSWORD_RESET.value,
            )
            .order_by(EmailVerificationToken.created_at.desc())
            .first()
        )

        retry_after = RESEND_PASSWORD_RESET_MIN_INTERVAL_SECONDS
        if latest is not None:
            wait_until = latest.created_at + timedelta(seconds=RESEND_PASSWORD_RESET_MIN_INTERVAL_SECONDS)
            remaining = (wait_until - now).total_seconds()
            retry_after = max(1, int(math.ceil(remaining)))
        
        log_security(
            "password_reset_rate_limited",
            user_id=user.id,
            retry_after=retry_after,
            client=(request.headers.get("cf-connecting-ip")
                    or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                    or getattr(request.client, "host", "-")),
            method=request.method,
            path=request.url.path,
        )

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"errors": {"_global": "重設密碼請求太頻繁，請稍後再試。"}},
            headers={"Retry-After": str(retry_after)},
        )

    log_security(
        "password_reset_email_sent",
        user_id=user.id,
        client=(request.headers.get("cf-connecting-ip")
                or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                or getattr(request.client, "host", "-")),
        method=request.method,
        path=request.url.path,
    )
    return {"ok": True}
