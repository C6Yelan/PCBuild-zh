# backend/api/routes/auth/verification/resend_verification.py
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session as OrmSession

from backend.api.dependencies.db import get_db
from backend.api.auth.config import EMAIL_ADAPTER, RESEND_SIGNUP_MIN_INTERVAL_SECONDS
from backend.api.auth.utils import raise_400
from backend.api.dependencies.auth import try_get_current_user
from backend.models import User
from backend.schemas.auth import ResendVerificationIn
from backend.services.auth.workflows.signup_verification import resend_signup_verification_for_email
from backend.services.auth.verification.core import VerificationEmailRateLimitedError
from backend.core.middleware.throttling.rate_limit import limiter
from backend.core.seclog import log_security, security_ctx

router = APIRouter()
_RESEND_GENERIC_OK = {
    "ok": True,
    "message": "If the account exists, you will receive an email.",
}


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
            return _RESEND_GENERIC_OK
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

    # 先查 user（僅用於內部審計；對外不暴露存在與否）
    user = db.query(User).filter(User.email == email).first()
    email_domain = email.split("@", 1)[-1].lower() if "@" in email else "-"
    if user is None:
        log_security(
            "email_verification_resend_suppressed",
            reason="user_not_found",
            email_domain=email_domain,
            **security_ctx(request),
        )
        return _RESEND_GENERIC_OK

    if user.is_active:
        log_security(
            "email_verification_resend_suppressed",
            reason="already_verified",
            user_id=user.id,
            email_domain=email_domain,
            **security_ctx(request),
        )
        return _RESEND_GENERIC_OK

    try:
        resend_signup_verification_for_email(db=db, email=email, request=request)
    except VerificationEmailRateLimitedError:
        log_security(
            "email_verification_resend_rate_limited",
            user_id=user.id,
            email_domain=email_domain,
            retry_after=RESEND_SIGNUP_MIN_INTERVAL_SECONDS,
            **security_ctx(request),
        )
        # 對外回應維持一致，避免可枚舉訊號（200 vs 429）
        return _RESEND_GENERIC_OK

    log_security(
        "email_verification_resent",
        user_id=user.id,
        email_domain=email_domain,
        client=(request.headers.get("cf-connecting-ip")
                or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                or getattr(request.client, "host", "-")),
        method=request.method,
        path=request.url.path,
    )
    # C) 一律回成功（避免暴露帳號是否存在/是否已驗證）
    return _RESEND_GENERIC_OK
