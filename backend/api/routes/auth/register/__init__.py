# backend/api/routes/auth/register/__init__.py
from fastapi import APIRouter, Depends, Request, Response

from sqlalchemy.orm import Session as OrmSession

from backend.api.dependencies.db import get_db
from backend.api.auth.config import EMAIL_ADAPTER
from backend.api.auth.utils import raise_400
from backend.models import User
from backend.schemas.auth import RegisterIn
from backend.security import hash_password
from backend.services.auth.workflows.signup_verification import send_signup_verification_for_user
from backend.core.middleware.throttling.rate_limit import limiter
from backend.core.seclog import log_security, security_ctx

router = APIRouter()

_REGISTER_GENERIC_OK = {
    "ok": True,
    "message": "If the account is eligible, you will receive an email.",
}


# ===== 註冊 =====
@router.post("/register")
@limiter.shared_limit("10/minute", scope="email_actions")
def register(
    body: RegisterIn,
    request: Request,
    response: Response, # <- 新增這行（符合 SlowAPI headers_enabled=True 的要求）
    db: OrmSession = Depends(get_db),
) -> dict[str, object]:
    ctx = security_ctx(request)
    # 1. 檢查 Email 格式（避免 Pydantic 回 422）
    try:
        EMAIL_ADAPTER.validate_python(body.email)
    except Exception:
        raise_400({"email": "Email 格式不正確。"})

    # 2. 檢查 Email / 使用者名稱是否已存在（對外不回傳可枚舉資訊）
    email_exists = db.query(User).filter(User.email == body.email).first() is not None
    username_exists = db.query(User).filter(User.username == body.username).first() is not None
    if email_exists or username_exists:
        email_domain = body.email.split("@", 1)[-1].lower() if "@" in body.email else "-"
        if email_exists:
            log_security(
                "register_suppressed_existing_email",
                email_domain=email_domain,
                **ctx,
            )
        if username_exists:
            log_security(
                "register_suppressed_existing_username",
                email_domain=email_domain,
                **ctx,
            )
        return _REGISTER_GENERIC_OK

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

    log_security(
        "register_accepted",
        email_domain=(body.email.split("@", 1)[-1].lower() if "@" in body.email else "-"),
        **ctx,
    )
    # 6. 對外一律回泛化成功訊息，避免帳號枚舉
    return _REGISTER_GENERIC_OK
