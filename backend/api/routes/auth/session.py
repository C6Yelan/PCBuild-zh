# backend/api/routes/auth/session.py
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session as OrmSession

from backend.api.deps import get_db
from backend.api.auth_config import (
    EMAIL_ADAPTER,
    SESSION_COOKIE_NAME,
    SESSION_EXPIRES_MINUTES,
)
from backend.api.auth_utils import raise_400, clear_session_cookie
from backend.models import User, Session as SessionModel
from backend.schemas.auth import LoginIn
from backend.security import verify_password

router = APIRouter()


@router.post("/login")
def login(
    body: LoginIn,
    response: Response,
    db: OrmSession = Depends(get_db),
):
    # 1. 檢查 Email 格式
    try:
        EMAIL_ADAPTER.validate_python(body.email)
    except Exception:
        raise_400({"email": "Email 格式不正確。"})

    # 2. 驗證帳號密碼
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.password_hash):
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

        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=str(session.id),
            max_age=int(ttl.total_seconds()),
            httponly=True,
            secure=True,
            samesite="Lax",
            path="/",
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

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=str(session.id),
        max_age=int(ttl.total_seconds()),
        httponly=True,
        secure=True,
        samesite="Lax",
        path="/",
    )
    return {"ok": True}


@router.post("/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    db: OrmSession = Depends(get_db),
):
    """
    將目前 session 標記為 revoked，並清除瀏覽器 Cookie。
    未登入時呼叫也回 204，不暴露細節。
    """
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)

    if raw_token:
        try:
            session_id = UUID(raw_token)
            session = (
                db.query(SessionModel)
                .filter(SessionModel.id == session_id, SessionModel.revoked.is_(False))
                .first()
            )
            if session:
                session.revoked = True
                db.commit()
        except ValueError:
            # Cookie 不是合法 UUID，忽略即可
            pass

    clear_session_cookie(response)
    return
