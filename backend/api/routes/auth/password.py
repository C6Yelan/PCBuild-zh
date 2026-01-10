# backend/api/routes/auth/password.py
import math
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session as OrmSession

from backend.api.deps import get_db
from backend.api.auth_config import EMAIL_ADAPTER, RESEND_MIN_INTERVAL_SECONDS
from backend.api.auth_utils import clear_session_cookie, raise_400
from backend.models import User, Session as SessionModel, EmailVerificationToken
from backend.schemas.auth import ForgotPasswordIn, ResetPasswordIn
from backend.security import hash_password, verify_password
from backend.services.auth.email_verification import (
    InvalidOrExpiredTokenError,
    VerificationEmailRateLimitedError,
    send_password_reset_for_user,
    VerificationPurpose,
    consume_verification_token,
    load_valid_token_and_user,
)

router = APIRouter()


# ===== 忘記密碼：從 Email 連結進入重設頁面 =====
@router.get("/reset-password/{token}", name="reset_password")
def reset_password_entry(
    token: str,
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
        # 對使用者一律顯示「已失效」
        return RedirectResponse(
            url="/reset-password-failed.html",
            status_code=status.HTTP_302_FOUND,
        )

    return RedirectResponse(
        url=f"/reset-password.html?token={token}",
        status_code=status.HTTP_302_FOUND,
    )


# ===== 忘記密碼：發送重設密碼信 =====
@router.post("/forgot-password")
def forgot_password(
    body: ForgotPasswordIn,
    request: Request,
    db: OrmSession = Depends(get_db),
):
    """
    忘記密碼入口：

    - 一律回傳 200 + {"ok": True}（不暴露帳號是否存在 / 是否已啟用）
    - 若 email 格式錯誤，回 400 提示使用者修正
    - 若帳號存在，才實際發 PASSWORD_RESET token 並寄信
    - 若請求過於頻繁，回 429 告知稍後再試
    """
    # 1. 檢查 Email 格式（只檢查字串是否合法，不洩漏帳號存在與否）
    try:
        EMAIL_ADAPTER.validate_python(body.email)
    except Exception:
        raise_400({"email": "Email 格式不正確。"})

    # 2. 查詢使用者（不論結果，對外回應統一）
    user = db.query(User).filter(User.email == body.email).first()

    # 3. 帳號不存在：仍回固定成功（不暴露是否存在）
    if not user:
        return {"ok": True}

    # 4. 帳號存在：不論是否已啟用，都發 PASSWORD_RESET token 並寄信
    try:
        send_password_reset_for_user(db=db, user=user, request=request)
    except VerificationEmailRateLimitedError:
        # 冷卻期間內：回 429，並用 Retry-After 提供「後端計算」的剩餘秒數
        now = datetime.now(timezone.utc)
        latest = (
            db.query(EmailVerificationToken)
            .filter(
                EmailVerificationToken.user_id == user.id,
                EmailVerificationToken.purpose == VerificationPurpose.PASSWORD_RESET.value,
            )
            .order_by(EmailVerificationToken.created_at.desc())
            .first()
        )

        retry_after = RESEND_MIN_INTERVAL_SECONDS
        if latest is not None:
            wait_until = latest.created_at + timedelta(seconds=RESEND_MIN_INTERVAL_SECONDS)
            remaining = (wait_until - now).total_seconds()
            retry_after = max(1, int(math.ceil(remaining)))

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"errors": {"_global": "重設密碼請求太頻繁，請稍後再試。"}},
            headers={"Retry-After": str(retry_after)},
        )

    return {"ok": True}


# ===== 忘記密碼：重設密碼 =====
@router.post("/reset-password")
def reset_password(
    body: ResetPasswordIn,
    response: Response,
    db: OrmSession = Depends(get_db),
):
    # 1) 驗證/消費 token（不在這裡 commit，由本 endpoint 統一 commit）
    try:
        user, token = consume_verification_token(
            db,
            body.token,
            purpose=VerificationPurpose.PASSWORD_RESET,
        )
    except InvalidOrExpiredTokenError:
        # 前端會依狀態導到「過期/已使用/格式錯誤」頁；API 端統一用 400 回覆即可
        raise_400({"token": "重設密碼連結無效或已過期，請重新申請。"})
        raise  # 只是讓型別檢查器安靜

    # 2) 新密碼不可與目前密碼相同
    # verify_password(plain, hash) 會用 Argon2 驗證是否同一密碼
    if verify_password(body.password, user.password_hash):
        db.rollback()  # 避免 token 被標記使用的狀態留在 session 中（不 commit 也保守 rollback）
        raise_400({"password": "新密碼不可與原密碼相同，請重新設定。"})

    # 3) 更新密碼（Argon2id）
    user.password_hash = hash_password(body.password)

    # 3-b) 將「完成重設密碼」視為 email 可用：若尚未啟用，直接啟用
    if not user.is_active:
        user.is_active = True

    # 4) 讓該使用者所有登入中的 session 失效（保留紀錄：revoked=True）
    db.query(SessionModel).filter(
        SessionModel.user_id == user.id,
        SessionModel.revoked.is_(False),
    ).update(
        {"revoked": True},
        synchronize_session=False,
    )

    db.commit()

    # 5) 清掉目前裝置 cookie，確保一定回到未登入狀態（導回登入頁）
    clear_session_cookie(response)
    return {"ok": True}
