# backend/api/routes/auth/register/__init__.py
from fastapi import APIRouter, Depends, Request, Response

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

    # 2. 檢查 Email / 使用者名稱是否已存在（一次收集所有欄位錯誤）
    errors: dict[str, str] = {}

    if db.query(User).filter(User.email == body.email).first():
        errors["email"] = "Email 已被註冊。"

    if db.query(User).filter(User.username == body.username).first():
        errors["username"] = "使用者名稱已被註冊。"

    if errors:
        raise_400(errors)

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
    send_signup_verification_for_user(
        db=db,
        user=user,
        request=request,
    )

    # 6. 回傳基本資訊（前端只拿來判斷成功與否）
    return RegisterOut(
        id=user.id,
        email=user.email,
        username=user.username,
        created_at=user.created_at,
    )
