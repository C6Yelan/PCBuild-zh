# backend/api/auth_utils.py
from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException, Request, Response, status
from sqlalchemy.orm import Session as OrmSession

from backend.api.auth_config import SESSION_COOKIE_NAME
from backend.models import Session as SessionModel


def clear_session_cookie(resp: Response) -> None:
    # 用 set_cookie 清除，帶上與設定時一致的屬性，避免部分瀏覽器刪不掉
    resp.set_cookie(
        key=SESSION_COOKIE_NAME,
        value="",
        max_age=0,
        expires=0,
        httponly=True,
        secure=True,
        samesite="Lax",
        path="/",
    )


def get_valid_session_from_request(request: Request, db: OrmSession) -> SessionModel | None:
    raw = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw:
        return None

    try:
        sid = UUID(raw)
    except Exception:
        return None

    now = datetime.now(timezone.utc)
    return (
        db.query(SessionModel)
        .filter(
            SessionModel.id == sid,
            SessionModel.revoked.is_(False),
            SessionModel.expires_at > now,
        )
        .first()
    )


def raise_400(errors: dict[str, str]) -> None:
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"errors": errors},
    )
