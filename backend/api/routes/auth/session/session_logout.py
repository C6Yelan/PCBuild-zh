# backend/api/routes/auth/session/session_logout.py
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session as OrmSession

from backend.api.dependencies.db import get_db
from backend.api.auth.config import SESSION_COOKIE_NAME
from backend.api.auth.utils import clear_session_cookie
from backend.models import Session as SessionModel
from backend.core.seclog import log_security, security_ctx

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
    ctx = security_ctx(request)

    raw_token = request.cookies.get(SESSION_COOKIE_NAME)

    if raw_token:
        try:
            session_id = UUID(raw_token)
        except ValueError:
            # Cookie 不是合法 UUID：記錄可疑行為，但仍回 204
            log_security(
                "session_invalid_cookie",
                endpoint="logout",
                **ctx,
            )
        else:
            session = (
                db.query(SessionModel)
                .filter(SessionModel.id == session_id, SessionModel.revoked.is_(False))
                .first()
            )
            if session:
                session.revoked = True
                db.commit()

                # 成功撤銷：這是高價值審計事件
                log_security(
                    "session_revoked",
                    reason="logout",
                    user_id=session.user_id,
                    session_kind=(getattr(session, "kind", None) or "login"),
                    **ctx,
                )

    clear_session_cookie(response)
    return