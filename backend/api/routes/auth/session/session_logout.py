# backend/api/routes/auth/session/session_logout.py
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session as OrmSession

from backend.api.dependencies.db import get_db
from backend.api.auth.config import SESSION_COOKIE_NAME
from backend.api.auth.utils import clear_session_cookie
from backend.models import Session as SessionModel
from backend.core.seclog import log_security

router = APIRouter()


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
                log_security(
                    "session_revoked",
                    reason="logout",
                    user_id=session.user_id,
                    session_kind=(session.kind or "login"),
                    client=(request.headers.get("cf-connecting-ip")
                            or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                            or getattr(request.client, "host", "-")),
                    method=request.method,
                    path=request.url.path,
                )
        except ValueError:
            log_security(
                "session_cookie_invalid",
                client=(request.headers.get("cf-connecting-ip")
                        or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                        or getattr(request.client, "host", "-")),
                method=request.method,
                path=request.url.path,
            )
            pass

    clear_session_cookie(response)
    return
