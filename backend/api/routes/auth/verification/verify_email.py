# backend/api/routes/auth/verification/verify_email.py
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session as OrmSession

from backend.api.dependencies.db import get_db
from backend.api.auth.config import SESSION_COOKIE_NAME
from backend.api.auth.utils import clear_session_cookie, get_valid_session_from_request, set_session_cookie
from backend.models import Session as SessionModel
from backend.services.auth.workflows.signup_verification import verify_signup_token_and_activate_user
from backend.services.auth.verification.core import InvalidOrExpiredTokenError
from backend.core.seclog import log_security, security_ctx

router = APIRouter()


# ===== Email Verification =====
@router.get("/verify-email/{token}", name="verify_email")
def verify_email(
    token: str,
    request: Request,
    db: OrmSession = Depends(get_db),
):
    ctx = security_ctx(request, include_path=False)
    # 1) 先驗證 token + 啟用帳號
    try:
        user = verify_signup_token_and_activate_user(db=db, public_token=token)
        log_security(
            "email_verify_success",
            user_id=user.id,
            endpoint="verify_email",
            **ctx,
        )
    except InvalidOrExpiredTokenError:
        log_security(
            "email_verify_token_invalid",
            endpoint="verify_email",
            **ctx,
        )
        return RedirectResponse(url="/verify-email-failed.html", status_code=status.HTTP_302_FOUND)

    def _success(mode: str) -> RedirectResponse:
        # mode 只表達顯示邏輯，不包含任何隱私資訊
        return RedirectResponse(
            url=f"/verify-email-success.html?mode={mode}",
            status_code=status.HTTP_302_FOUND,
        )

    # 2) 取得目前 cookie 對應的有效 session（可能沒有）
    raw_cookie = request.cookies.get(SESSION_COOKIE_NAME)
    current_session = get_valid_session_from_request(request, db)

    # 沒有合法 session：顯示成功頁，並引導前往登入
    if not current_session:
        if raw_cookie:
            log_security(
                "session_invalid_cookie",
                endpoint="verify_email",
                **ctx,
            )
        resp = _success("login")
        if raw_cookie:
            clear_session_cookie(resp)
        return resp

    # 3) 有 session，但 user 不同：登出目前 session，要求重新登入
    if current_session.user_id != user.id:
        log_security(
            "email_verify_session_mismatch",
            session_user_id=current_session.user_id,
            verified_user_id=user.id,
            session_kind=(current_session.kind or "login"),
            endpoint="verify_email",
            **ctx,
        )

        current_session.revoked = True
        db.add(current_session)
        db.commit()

        log_security(
            "session_revoked",
            reason="verify_email_user_mismatch",
            user_id=current_session.user_id,
            session_kind=(current_session.kind or "login"),
            endpoint="verify_email",
            **ctx,
        )

        resp = _success("login")
        clear_session_cookie(resp)
        return resp

    # 4) session user 相同：一定顯示成功頁（依你最新要求）
    # 4-a) 若是 signup session：清 cookie，要求重新登入
    if (current_session.kind or "login") == "signup":
        current_session.revoked = True
        db.add(current_session)
        db.commit()
        log_security(
            "session_revoked",
            reason="verify_email_signup_session",
            user_id=user.id,
            session_kind="signup",
            endpoint="verify_email",
            **ctx,
        )

        resp = _success("login")
        clear_session_cookie(resp)
        return resp

    # 4-b) 若是 login session：保留登入狀態，但做 session rotation（避免狀態升級沿用舊 session）
    now = datetime.now(timezone.utc)
    remaining = current_session.expires_at - now
    max_age = max(1, int(remaining.total_seconds()))

    new_session = SessionModel(
        id=uuid4(),
        user_id=user.id,
        expires_at=current_session.expires_at,  # 保留剩餘有效期
        kind="login",
    )
    current_session.revoked = True

    db.add(new_session)
    db.add(current_session)
    db.commit()

    log_security(
        "session_rotated",
        reason="verify_email_privilege_upgrade",
        user_id=user.id,
        session_kind="login",
        endpoint="verify_email",
        **ctx,
    )

    resp = _success("home")
    set_session_cookie(resp, str(new_session.id), max_age=max_age)
    return resp