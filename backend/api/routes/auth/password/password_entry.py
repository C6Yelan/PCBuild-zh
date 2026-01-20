# backend/api/routes/auth/password/password_entry.py
from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session as OrmSession

from backend.api.dependencies.db import get_db
from backend.services.auth.tokens.email_tokens import load_valid_token_and_user
from backend.services.auth.verification.core import (
    InvalidOrExpiredTokenError,
    VerificationPurpose,
)
from backend.core.middleware.throttling.rate_limit import limiter
from backend.core.seclog import log_security

router = APIRouter()


# ===== 忘記密碼：從 Email 連結進入重設頁面 =====
@router.get("/reset-password/{token}", name="reset_password")
@limiter.shared_limit("20/minute", scope="auth_sensitive")
@limiter.limit("10/minute")
def reset_password_entry(
    token: str,
    request: Request,  # ← 新增（即使函式內不用）
    db: OrmSession = Depends(get_db),
):
    """
    忘記密碼 Email 連結入口。

    - token 有效：導向 /reset-password.html?token=...
    - token 無效/已失效（含過期、已使用、被取代、格式錯誤等）：一律導向失效頁
      （前端統一顯示「已失效」）
    """
    try:
        # 只驗證，不消費、不 commit；並套用 PASSWORD_RESET「僅最新 token 有效」規則
        load_valid_token_and_user(
            db=db,
            public_token=token,
            expected_purpose=VerificationPurpose.PASSWORD_RESET,
        )
    except InvalidOrExpiredTokenError:
        log_security(
            "password_reset_token_invalid",
            endpoint="reset_password_entry",
            client=(request.headers.get("cf-connecting-ip")
                    or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
                    or getattr(request.client, "host", "-")),
            method="GET",
        )
        return RedirectResponse(
            url="/reset-password-failed.html",
            status_code=status.HTTP_302_FOUND,
        )
    
    log_security(
    "password_reset_token_valid",
    endpoint="reset_password_entry",
    client=(request.headers.get("cf-connecting-ip")
            or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
            or getattr(request.client, "host", "-")),
    method="GET",
    )
    
    return RedirectResponse(
        url=f"/reset-password.html?token={token}",
        status_code=status.HTTP_302_FOUND,
    )
