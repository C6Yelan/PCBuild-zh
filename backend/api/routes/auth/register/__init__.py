# backend/api/routes/auth/register/__init__.py
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from sqlalchemy.orm import Session as OrmSession

from backend.api.dependencies.db import get_db
from backend.api.auth.config import EMAIL_ADAPTER
from backend.api.auth.utils import raise_400
from backend.models import User
from backend.schemas.auth import RegisterIn, RegisterOut
from backend.security import hash_password
from backend.services.auth.workflows.signup_verification import send_signup_verification_for_user
from backend.core.middleware.throttling.rate_limit import limiter

router = APIRouter()
logger = logging.getLogger(__name__)


# ===== 註冊 =====
@router.post("/register", response_model=RegisterOut)
@limiter.shared_limit("10/minute", scope="email_actions")
def register(
    body: RegisterIn,
    request: Request,
    response: Response, # <- 新增這行（符合 SlowAPI headers_enabled=True 的要求）
    db: OrmSession = Depends(get_db),
) -> RegisterOut:
    # 1. 檢查 Email 格式（避免 Pydantic 回 422）
    try:
        EMAIL_ADAPTER.validate_python(body.email)
    except Exception:
        raise_400({"email": "Email 格式不正確。"})

    # 2. 檢查 Email / 使用者名稱是否已存在
    # 回傳全域訊息，避免直接暴露是 email 或 username 命中重複。
    if (
        db.query(User).filter(User.email == body.email).first()
        or db.query(User).filter(User.username == body.username).first()
    ):
        raise_400({"_global": "註冊資料不可用，請確認後再試。"})

    # 3. 建立使用者（預設為未啟用，待 Email 驗證後啟用）
    hashed = hash_password(body.password)
    user = User(
        email=body.email,
        username=body.username,
        password_hash=hashed,
        is_active=False,  # 註冊完成但尚未通過信箱驗證
        is_admin=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # 5. 寄出註冊驗證信（使用 url_for 產生驗證連結）
    try:
        send_signup_verification_for_user(
            db=db,
            user=user,
            request=request,
        )
    except Exception:
        logger.exception("signup_verification_send_failed user_id=%s", user.id)
        db.rollback()
        # 避免出現「前端顯示註冊失敗，但 DB 已有帳號」的不一致狀態
        try:
            db.delete(user)
            db.commit()
        except Exception:
            db.rollback()

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"errors": {"_global": "驗證信寄送失敗，請稍後再試。"}},
        )

    # 6. 回傳基本資訊（前端只拿來判斷成功與否）
    return RegisterOut(
        ok=True,
        id=user.id,
        email=user.email,
        username=user.username,
        created_at=user.created_at,
    )
