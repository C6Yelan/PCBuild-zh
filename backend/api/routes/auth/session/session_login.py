# backend/api/routes/auth/session/session_login.py
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session as OrmSession

from backend.api.dependencies.db import get_db
from backend.api.auth.config import (
    EMAIL_ADAPTER,
    SESSION_EXPIRES_MINUTES,
)
from backend.api.auth.utils import raise_400, set_session_cookie
from backend.models import User, Session as SessionModel
from backend.schemas.auth import LoginIn
from backend.security import verify_password
from backend.core.middleware.throttling.rate_limit import limiter
from backend.core.seclog import log_security

router = APIRouter()


@router.post("/login")
@limiter.shared_limit("20/minute", scope="auth_sensitive")
@limiter.limit("10/minute")
def login(
    body: LoginIn,
    request: Request,   # ← 新增（SlowAPI 需要）
    response: Response,
    db: OrmSession = Depends(get_db),
):
    # 1. 檢查 Email 格式
    try:
        EMAIL_ADAPTER.validate_python(body.email)
    except Exception:
        log_security(
            "authn_input_invalid",
            reason="email_format",
            client=(request.headers.get("cf-connecting-ip")
                    or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                    or getattr(request.client, "host", "-")),
            method=request.method,
            path=request.url.path,
        )
        raise_400({"email": "Email 格式不正確。"})

    # 2. 驗證帳號密碼
    user = db.query(User).filter(User.email == body.email).first()
    email_domain = body.email.split("@", 1)[-1].lower() if "@" in body.email else "-"
    if not user or not verify_password(body.password, user.password_hash):
        log_security(
            "authn_failed",
            reason="invalid_credentials",
            email_domain=email_domain,
            client=(request.headers.get("cf-connecting-ip")
                    or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                    or getattr(request.client, "host", "-")),
            method=request.method,
            path=request.url.path,
        )
        raise_400({"credentials": "帳號或密碼錯誤。"})

    # 3. 尚未完成 Email 驗證：建立 session，允許「受限登入」
    if not user.is_active:
        now = datetime.now(timezone.utc)
        ttl = timedelta(minutes=SESSION_EXPIRES_MINUTES)
        expires_at = now + ttl

        session = SessionModel(
            id=uuid4(),
            user_id=user.id,
            expires_at=expires_at,
            kind="login",
        )
        db.add(session)
        db.commit()

        log_security(
            "session_created",
            user_id=user.id,
            session_kind="login",
            account_state="inactive",
            client=(request.headers.get("cf-connecting-ip")
                    or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                    or getattr(request.client, "host", "-")),
            method=request.method,
            path=request.url.path,
        )

        set_session_cookie(response, str(session.id))

        log_security(
            "authn_success",
            user_id=user.id,
            account_state="inactive",
            outcome="needs_verification",
            client=(request.headers.get("cf-connecting-ip")
                    or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                    or getattr(request.client, "host", "-")),
            method=request.method,
            path=request.url.path,
        )

        return {"ok": True, "needs_verification": True}

    # 4. 已啟用帳號：正常登入流程
    now = datetime.now(timezone.utc)
    ttl = timedelta(minutes=SESSION_EXPIRES_MINUTES)
    expires_at = now + ttl

    session = SessionModel(
        id=uuid4(),
        user_id=user.id,
        expires_at=expires_at,
        kind="login",
    )
    db.add(session)
    db.commit()

    log_security(
        "session_created",
        user_id=user.id,
        session_kind="login",
        account_state="active",
        client=(request.headers.get("cf-connecting-ip")
                or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                or getattr(request.client, "host", "-")),
        method=request.method,
        path=request.url.path,
    )

    set_session_cookie(response, str(session.id))

    log_security(
        "authn_success",
        user_id=user.id,
        account_state="active",
        outcome="ok",
        client=(request.headers.get("cf-connecting-ip")
                or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                or getattr(request.client, "host", "-")),
        method=request.method,
        path=request.url.path,
    )

    return {"ok": True}
