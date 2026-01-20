# backend/api/routes/auth/password/password_reset.py
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session as OrmSession

from backend.api.dependencies.db import get_db
from backend.api.auth.utils import clear_session_cookie, raise_400
from backend.models import Session as SessionModel
from backend.schemas.auth import ResetPasswordIn
from backend.security import hash_password, verify_password
from backend.services.auth.tokens.email_tokens import consume_verification_token
from backend.services.auth.verification.core import (
    InvalidOrExpiredTokenError,
    VerificationPurpose,
)
from backend.core.middleware.throttling.rate_limit import limiter
from backend.core.seclog import log_security, security_ctx

router = APIRouter()


# ===== 忘記密碼：重設密碼 =====
@router.post("/reset-password")
@limiter.shared_limit("20/minute", scope="auth_sensitive")
@limiter.limit("5/minute")
def reset_password(
    body: ResetPasswordIn,
    request: Request,  # ← 新增（即使函式內不用）
    response: Response,
    db: OrmSession = Depends(get_db),
):
    try:
        user, _token = consume_verification_token(
            db,
            body.token,
            purpose=VerificationPurpose.PASSWORD_RESET,
        )
    except InvalidOrExpiredTokenError:
        log_security(
            "password_reset_token_invalid",
            endpoint="reset_password",
            client=(request.headers.get("cf-connecting-ip")
                    or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                    or getattr(request.client, "host", "-")),
            method=request.method,
            path=request.url.path,
        )
        raise_400({"token": "重設密碼連結無效或已過期，請重新申請。"})
        raise

    if verify_password(body.password, user.password_hash):
        log_security(
            "password_reset_policy_violation",
            reason="same_as_old_password",
            user_id=user.id,
            client=(request.headers.get("cf-connecting-ip")
                    or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                    or getattr(request.client, "host", "-")),
            method=request.method,
            path=request.url.path,
        )
        db.rollback()
        raise_400({"password": "新密碼不可與原密碼相同，請重新設定。"})

    user.password_hash = hash_password(body.password)

    was_inactive = not user.is_active
    if was_inactive:
        user.is_active = True

    revoked_sessions = db.query(SessionModel).filter(
        SessionModel.user_id == user.id,
        SessionModel.revoked.is_(False),
    ).update(
        {"revoked": True},
        synchronize_session=False,
    )

    db.commit()

    log_security(
        "password_reset_success",
        user_id=user.id,
        revoked_sessions=revoked_sessions,
        account_activated=("1" if was_inactive else "0"),
        **security_ctx(request),
    )

    clear_session_cookie(response)
    return {"ok": True}
