# backend/api/routes/auth/verification/resend_verification.py
import math
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session as OrmSession

from backend.api.dependencies.db import get_db
from backend.api.auth.config import EMAIL_ADAPTER, RESEND_SIGNUP_MIN_INTERVAL_SECONDS
from backend.api.auth.utils import raise_400
from backend.api.dependencies.auth import try_get_current_user
from backend.models import User, EmailVerificationToken
from backend.schemas.auth import ResendVerificationIn
from backend.services.auth.workflows.signup_verification import resend_signup_verification_for_email
from backend.services.auth.verification.core import (
    VerificationEmailRateLimitedError,
    VerificationPurpose,
)
from backend.core.middleware.throttling.rate_limit import limiter
from backend.core.seclog import log_security, security_ctx

router = APIRouter()


# ===== 重新寄送驗證信 =====
@router.post("/resend-verification")
@limiter.shared_limit("10/minute", scope="email_actions")
def resend_verification(
    body: ResendVerificationIn,
    request: Request,
    response: Response,
    db: OrmSession = Depends(get_db),
):
    # 所有成功回覆都帶 Retry-After，讓前端不用猜 60 秒
    response.headers["Retry-After"] = str(RESEND_SIGNUP_MIN_INTERVAL_SECONDS)

    # 0) email 可能是 None
    email = (getattr(body, "email", None) or "").strip()

    # A) 沒帶 email：走 session（給 index 的事件導向用）
    if not email:
        current_user = try_get_current_user(request=request, db=db)
        if not current_user:
            log_security("email_verification_resend_anonymous", **security_ctx(request))
            return {"ok": True}
        email = current_user.email

    # B) 有 email（或從 session 推到 email）：才做格式檢查與寄送
    try:
        EMAIL_ADAPTER.validate_python(email)
    except Exception:
        log_security(
            "authn_input_invalid",
            reason="email_format",
            endpoint="resend_verification",
            client=(request.headers.get("cf-connecting-ip")
                    or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                    or getattr(request.client, "host", "-")),
            method=request.method,
            path=request.url.path,
        )
        raise_400({"email": "Email 格式不正確。"})

    # 先查 user（用於限流時精準算剩餘秒數；不存在/已啟用也不暴露）
    user = db.query(User).filter(User.email == email).first()

    try:
        resend_signup_verification_for_email(db=db, email=email, request=request)
    except VerificationEmailRateLimitedError:
        retry_after = RESEND_SIGNUP_MIN_INTERVAL_SECONDS

        # 若查得到 user（且尚未啟用），用最新 token.created_at 精準計算剩餘秒數
        if user is not None and not user.is_active:
            latest = (
                db.query(EmailVerificationToken)
                .filter(
                    EmailVerificationToken.user_id == user.id,
                    EmailVerificationToken.purpose == VerificationPurpose.SIGNUP.value,
                )
                .order_by(EmailVerificationToken.created_at.desc())
                .first()
            )
            if latest is not None:
                now = datetime.now(timezone.utc)
                wait_until = latest.created_at + timedelta(seconds=RESEND_SIGNUP_MIN_INTERVAL_SECONDS)
                remaining = (wait_until - now).total_seconds()
                retry_after = max(1, int(math.ceil(remaining)))
                
        email_domain = email.split("@", 1)[-1].lower() if "@" in email else "-"
        log_security(
            "email_verification_resend_rate_limited",
            user_id=(user.id if (user is not None) else "-"),
            email_domain=email_domain,
            retry_after=retry_after,
            **security_ctx(request),
        )
        response.headers["Retry-After"] = str(retry_after)
        return {"ok": True}

    email_domain = email.split("@", 1)[-1].lower() if "@" in email else "-"
    log_security(
        "email_verification_resent",
        user_id=(user.id if (user is not None) else "-"),
        email_domain=email_domain,
        client=(request.headers.get("cf-connecting-ip")
                or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                or getattr(request.client, "host", "-")),
        method=request.method,
        path=request.url.path,
    )
    # C) 一律回成功（避免暴露帳號是否存在/是否已驗證）
    return {"ok": True}
