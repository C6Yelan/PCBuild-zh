# backend/api/dependencies/auth.py
from datetime import datetime, timezone
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as OrmSession

from backend.api.auth.config import SESSION_COOKIE_NAME
from backend.api.dependencies.db import get_db
from backend.models import User, Session as SessionModel
from backend.core.seclog import log_security, security_ctx


def _unauthenticated() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="未登入或憑證已失效",
    )


def _resolve_current_user(
    request: Request,
    db: OrmSession,
    *,
    emit_log: bool,
) -> User | None:
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw_token:
        if emit_log:
            log_security("authn_missing_session_cookie", **security_ctx(request))
        return None

    try:
        session_id = UUID(raw_token)
    except ValueError:
        if emit_log:
            log_security("session_cookie_invalid", **security_ctx(request))
        return None

    now = datetime.now(timezone.utc)

    session = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if not session:
        if emit_log:
            log_security("session_not_found", **security_ctx(request))
        return None

    if session.revoked:
        if emit_log:
            log_security(
                "session_revoked",
                reason="revoked",
                user_id=session.user_id,
                session_kind=(session.kind or "login"),
                **security_ctx(request),
            )
        return None

    if session.expires_at <= now:
        if emit_log:
            log_security(
                "session_expired",
                user_id=session.user_id,
                session_kind=(session.kind or "login"),
                **security_ctx(request),
            )
        return None

    user = db.query(User).filter(User.id == session.user_id).first()
    if not user:
        if emit_log:
            log_security(
                "session_user_missing",
                user_id=session.user_id,
                session_kind=(session.kind or "login"),
                **security_ctx(request),
            )
        return None

    return user


def try_get_current_user(
    request: Request,
    db: OrmSession,
) -> User | None:
    """不丟例外、不寫 security log；用於『不想暴露狀態且不想產生噪音』的路由。"""
    return _resolve_current_user(request=request, db=db, emit_log=False)


def get_current_user(
    request: Request,
    db: OrmSession = Depends(get_db),
) -> User:
    user = _resolve_current_user(request=request, db=db, emit_log=True)
    if not user:
        raise _unauthenticated()
    return user


def get_active_user(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_active:
        log_security(
            "authz_denied",
            reason="email_unverified",
            user_id=current_user.id,
            **security_ctx(request),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email 尚未驗證，請先完成信箱驗證。",
        )
    return current_user
