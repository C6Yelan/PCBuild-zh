# backend/api/routes/auth/password/forgot_password.py
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session as OrmSession

from backend.api.dependencies.db import get_db
from backend.api.auth.config import EMAIL_ADAPTER
from backend.api.auth.utils import raise_400
from backend.models import User
from backend.schemas.auth import ForgotPasswordIn
from backend.services.auth.workflows.password_reset import send_password_reset_for_user
from backend.services.auth.verification.core import VerificationEmailRateLimitedError
from backend.core.middleware.throttling.rate_limit import limiter
from backend.core.seclog import log_security, security_ctx

router = APIRouter()
_FORGOT_PASSWORD_GENERIC_OK = {
    "ok": True,
    "message": "If the account exists, you will receive an email.",
}


# ===== 忘記密碼：發送重設密碼信 =====
@router.post("/forgot-password")
@limiter.shared_limit("10/minute", scope="email_actions")
def forgot_password(
    body: ForgotPasswordIn,
    request: Request,
    response: Response, # <- 新增這行（符合 SlowAPI headers_enabled=True 的要求）
    db: OrmSession = Depends(get_db),
):
    ctx = security_ctx(request)
    """
    忘記密碼入口：

    - 一律回傳 200 + 泛化成功訊息（不暴露帳號是否存在 / 是否已啟用）
    - 若 email 格式錯誤，回 400 提示使用者修正
    - 若帳號存在，才實際發 PASSWORD_RESET token 並寄信
    - 若內部流程判定寄送過於頻繁，僅記錄安全事件，不回傳可枚舉訊號
    """
    try:
        EMAIL_ADAPTER.validate_python(body.email)
    except Exception:
        log_security(
            "authn_input_invalid",
            reason="email_format",
            endpoint="forgot_password",
            **ctx,
        )
        raise_400({"email": "Email 格式不正確。"})

    user = db.query(User).filter(User.email == body.email).first()
    if not user:
        email_domain = body.email.split("@", 1)[-1].lower() if "@" in body.email else "-"
        log_security(
            "password_reset_request_unknown",
            email_domain=email_domain,
            **ctx,
        )
        return _FORGOT_PASSWORD_GENERIC_OK

    try:
        send_password_reset_for_user(db=db, user=user, request=request)
    except VerificationEmailRateLimitedError:
        log_security(
            "password_reset_rate_limited",
            user_id=user.id,
            **ctx,
        )
        # 對外回應維持一致，避免可枚舉訊號（200 vs 429）
        return _FORGOT_PASSWORD_GENERIC_OK

    log_security(
        "password_reset_email_sent",
        user_id=user.id,
        **ctx,
    )
    return _FORGOT_PASSWORD_GENERIC_OK
