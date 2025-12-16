# backend/api/auth.py
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4, UUID

from argon2 import PasswordHasher, exceptions as argon2_exceptions
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session as OrmSession
from pydantic import EmailStr, TypeAdapter

from backend.api.deps import get_db
from backend.models import User, Session as SessionModel, EmailVerificationToken
from backend.schemas.auth import RegisterIn, RegisterOut, LoginIn, MeOut, ResendVerificationIn, ForgotPasswordIn, ResetPasswordIn, ResetPasswordOut
from backend.security import hash_password, verify_password
from backend.services.auth.email_verification import (
    send_signup_verification_for_user,
    verify_signup_token_and_activate_user,
    InvalidOrExpiredTokenError,
    resend_signup_verification_for_email,
    VerificationEmailRateLimitedError,
    send_password_reset_for_user,
    VerificationPurpose,
    consume_verification_token,
)
router = APIRouter(prefix="/api/auth", tags=["auth"])

EMAIL_ADAPTER = TypeAdapter(EmailStr)
SESSION_COOKIE_NAME = "pcbuild_session"
SESSION_EXPIRES_MINUTES = int(os.getenv("SESSION_EXPIRES_MINUTES", "120"))
RESEND_MIN_INTERVAL_SECONDS = 60  # 與前端倒數一致（1 分鐘）
# Argon2 hasher for verifying reset-password tokens
_reset_token_hasher = PasswordHasher()

# ===== 工具函式 =====
def _clear_session_cookie(resp: Response) -> None:
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

# ===== 從 Request 取得有效 Session（或 None） =====
def _get_valid_session_from_request(request: Request, db: OrmSession) -> SessionModel | None:
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


# ===== 共用錯誤拋出工具 =====

def _raise_400(errors: dict[str, str]) -> None:
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"errors": errors},
    )


# ===== 目前登入(未驗證)使用者依賴 =====

def get_current_user(
    request: Request,
    db: OrmSession = Depends(get_db),
) -> User:
    """
    從 HttpOnly Cookie (pcbuild_session) 取得目前登入的使用者。
    若 Cookie 不存在、session 無效或過期，一律回傳 401。
    """
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未登入或憑證已失效",
        )

    try:
        session_id = UUID(raw_token)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未登入或憑證已失效",
        )

    now = datetime.now(timezone.utc)

    session = (
        db.query(SessionModel)
        .filter(
            SessionModel.id == session_id,
            SessionModel.revoked.is_(False),
            SessionModel.expires_at > now,
        )
        .first()
    )

    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未登入或憑證已失效",
        )

    user = db.query(User).filter(User.id == session.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未登入或憑證已失效",
        )

    return user


# ===== 取得已啟用使用者依賴 =====
def get_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    僅允許「已登入且已完成 Email 驗證」的使用者通過。

    - 未登入：get_current_user 會先拋出 401
    - 已登入但尚未完成 Email 驗證：拋出 403
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email 尚未驗證，請先完成信箱驗證。",
        )
    return current_user


# ===== 取得目前登入使用者 =====

@router.get("/me", response_model=MeOut)
def get_me(current_user: User = Depends(get_current_user)) -> MeOut:
    return MeOut(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        is_admin=current_user.is_admin,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
    )


# ===== 註冊 =====

@router.post("/register", response_model=RegisterOut)
def register(
    body: RegisterIn,
    request: Request,
    response: Response,
    db: OrmSession = Depends(get_db),
) -> RegisterOut:
    # 1. 檢查 Email 格式（避免 Pydantic 回 422）
    try:
        EMAIL_ADAPTER.validate_python(body.email)
    except Exception:
        _raise_400({"email": "Email 格式不正確。"})

    # 2. 檢查 Email / 使用者名稱是否已存在（一次收集所有欄位錯誤）
    errors: dict[str, str] = {}

    if db.query(User).filter(User.email == body.email).first():
        errors["email"] = "Email 已被註冊。"

    if db.query(User).filter(User.username == body.username).first():
        errors["username"] = "使用者名稱已被註冊。"

    if errors:
        _raise_400(errors)

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

    # 4. 建立 session（與 /login 相同的安全設定）
    now = datetime.now(timezone.utc)
    ttl = timedelta(minutes=SESSION_EXPIRES_MINUTES)
    expires_at = now + ttl

    session = SessionModel(
        id=uuid4(),
        user_id=user.id,
        expires_at=expires_at,
        kind="signup",
    )
    db.add(session)
    db.commit()

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=str(session.id),
        max_age=int(ttl.total_seconds()),
        httponly=True,   # JS 讀不到，降低 XSS 風險
        secure=True,     # 僅在 HTTPS 下傳遞
        samesite="Lax",  # 降低 CSRF 風險
        path="/",
    )

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


# ===== Email Verification =====
@router.get("/verify-email/{token}", name="verify_email")
def verify_email(
    token: str,
    request: Request,
    db: OrmSession = Depends(get_db),
):
    # 1) 先驗證 token + 啟用帳號
    try:
        user = verify_signup_token_and_activate_user(db=db, public_token=token)
    except InvalidOrExpiredTokenError:
        return RedirectResponse(url="/verify-email-failed.html", status_code=status.HTTP_302_FOUND)

    def _success(mode: str) -> RedirectResponse:
        # mode 只表達顯示邏輯，不包含任何隱私資訊
        return RedirectResponse(
            url=f"/verify-email-success.html?mode={mode}",
            status_code=status.HTTP_302_FOUND,
        )

    # 2) 取得目前 cookie 對應的有效 session（可能沒有）
    raw_cookie = request.cookies.get(SESSION_COOKIE_NAME)
    current_session = _get_valid_session_from_request(request, db)

    # 沒有合法 session：顯示成功頁，並引導前往登入
    if not current_session:
        resp = _success("login")
        if raw_cookie:
            _clear_session_cookie(resp)
        return resp

    # 3) 有 session，但 user 不同：登出目前 session，要求重新登入
    if current_session.user_id != user.id:
        current_session.revoked = True
        db.add(current_session)
        db.commit()

        resp = _success("login")
        _clear_session_cookie(resp)
        return resp

    # 4) session user 相同：一定顯示成功頁（依你最新要求）
    # 4-a) 若是 signup session：清 cookie，要求重新登入
    if (current_session.kind or "login") == "signup":
        current_session.revoked = True
        db.add(current_session)
        db.commit()

        resp = _success("login")
        _clear_session_cookie(resp)
        return resp

    # 4-b) 若是 login session：保留登入狀態，但做 session rotation（避免狀態升級沿用舊 session）
    now = datetime.now(timezone.utc)
    remaining = current_session.expires_at - now
    max_age = max(1, int(remaining.total_seconds()))

    new_session = SessionModel(
        id=uuid4(),
        user_id=user.id,
        expires_at=current_session.expires_at,  # 保留剩餘有效期
        kind="login",
    )
    current_session.revoked = True

    db.add(new_session)
    db.add(current_session)
    db.commit()

    resp = _success("home")
    resp.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=str(new_session.id),
        max_age=max_age,
        httponly=True,
        secure=True,
        samesite="Lax",
        path="/",
    )
    return resp



# ===== 忘記密碼：從 Email 連結進入重設頁面 =====
@router.get("/reset-password/{token}", name="reset_password")
def reset_password_entry(
    token: str,
    db: OrmSession = Depends(get_db),
):
    """
    忘記密碼 Email 連結入口。

    依 token 狀態導向不同的前端頁面：
    - 有效：   /reset-password.html?token=...
    - 已使用： /reset-password-failed.html?reason=used
    - 已過期： /reset-password-failed.html?reason=expired
    - 格式錯誤 / 找不到 / secret 不匹配：/reset-password-failed.html?reason=invalid
    """

    # 1) 解析 token（<id>.<secret>）
    try:
        id_str, secret = token.split(".", 1)
        token_id = int(id_str)
        if not secret:
            raise ValueError("empty secret")
    except (ValueError, AttributeError):
        return RedirectResponse(
            url="/reset-password-failed.html?reason=invalid",
            status_code=status.HTTP_302_FOUND,
        )

    # 2) 先查 token_id + 用途
    row = (
        db.query(EmailVerificationToken)
        .filter(
            EmailVerificationToken.id == token_id,
            EmailVerificationToken.purpose == VerificationPurpose.PASSWORD_RESET.value,
        )
        .first()
    )
    if row is None:
        return RedirectResponse(
            url="/reset-password-failed.html?reason=invalid",
            status_code=status.HTTP_302_FOUND,
        )

    # 3) 核心修正：驗證 secret 是否匹配 token_hash
    #    若 secret 不匹配，直接視為 invalid（避免被竄改的 token 仍能打開重設頁）
    try:
        _reset_token_hasher.verify(row.token_hash, secret)
    except (
        argon2_exceptions.VerifyMismatchError,
        argon2_exceptions.VerificationError,
        Exception,
    ):
        return RedirectResponse(
            url="/reset-password-failed.html?reason=invalid",
            status_code=status.HTTP_302_FOUND,
        )

    # 4) secret 正確後，才允許顯示 used / expired 等狀態（避免 token_id 被枚舉探測）
    now = datetime.now(timezone.utc)

    # 4-1) 已使用
    if row.is_used:
        return RedirectResponse(
            url="/reset-password-failed.html?reason=used",
            status_code=status.HTTP_302_FOUND,
        )

    # 4-2) 過期
    if row.expires_at < now:
        return RedirectResponse(
            url="/reset-password-failed.html?reason=expired",
            status_code=status.HTTP_302_FOUND,
        )

    # 5) 有效：導向前端重設密碼頁面
    return RedirectResponse(
        url=f"/reset-password.html?token={token}",
        status_code=status.HTTP_302_FOUND,
    )


# ===== 重新寄送驗證信 =====
@router.post("/resend-verification")
def resend_verification(
    body: ResendVerificationIn,
    request: Request,
    db: OrmSession = Depends(get_db),
):
    # 1. 檢查 Email 格式
    try:
        EMAIL_ADAPTER.validate_python(body.email)
    except Exception:
        _raise_400({"email": "Email 格式不正確。"})

    # 2. 嘗試重新寄送驗證信
    try:
        resend_signup_verification_for_email(
            db=db,
            email=body.email,
            request=request,
        )
    except VerificationEmailRateLimitedError:
        # 過於頻繁，回 429，並用 Retry-After 告訴前端要等幾秒再試
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"errors": {"email": "驗證信寄送太頻繁，請稍後再試。"}},
            headers={"Retry-After": str(RESEND_MIN_INTERVAL_SECONDS)},
        )


    # 3. 一律回傳成功（不暴露帳號是否存在或是否已驗證）
    return {"ok": True}


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
    - 若帳號存在且已啟用，才實際發 PASSWORD_RESET token 並寄信
    - 若請求過於頻繁，回 429 告知稍後再試
    """
    # 1. 檢查 Email 格式（只檢查字串是否合法，不洩漏帳號存在與否）
    try:
        EMAIL_ADAPTER.validate_python(body.email)
    except Exception:
        _raise_400({"email": "Email 格式不正確。"})

    # 2. 查詢使用者（不論結果，對外回應統一）
    user = db.query(User).filter(User.email == body.email).first()

    # 3. 帳號不存在或尚未驗證：不寄信，直接回固定成功
    if not user or not user.is_active:
        return {"ok": True}

    # 4. 已啟用帳號：嘗試發行重設密碼 token + 寄信
    try:
        send_password_reset_for_user(
            db=db,
            user=user,
            request=request,
        )
    except VerificationEmailRateLimitedError:
        # 冷卻期間內：回 429，讓前端顯示「操作過於頻繁」
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"errors": {"email": "重設密碼請求太頻繁，請在 1 分鐘後再試。"}},
        )

    # 5. 一切正常：仍然只回固定成功結構，不提供帳號存不存在線索
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
        _raise_400({"token": "重設密碼連結無效或已過期，請重新申請。"})
        raise  # 只是讓型別檢查器安靜

    # 2) 未驗證帳號：不提供重設（但你前端仍顯示已寄出屬於 UX/防枚舉設計）
    if not user.is_active:
        _raise_400({"token": "重設密碼連結無效或已過期，請重新申請。"})
        raise

    # 3) 更新密碼（Argon2id）
    user.password_hash = hash_password(body.password)

    # 4) 使「該使用者所有 PASSWORD_RESET token」全部失效（包含其他尚未使用的）
    db.query(EmailVerificationToken).filter(
        EmailVerificationToken.user_id == user.id,
        EmailVerificationToken.purpose == VerificationPurpose.PASSWORD_RESET.value,
    ).update(
        {"is_used": True},
        synchronize_session=False,
    )

    # 5) 讓該使用者所有登入中的 session 失效（最保守的方式：直接刪除）
    db.query(SessionModel).filter(SessionModel.user_id == user.id).delete(
        synchronize_session=False
    )

    db.commit()

    # 6) 清掉目前裝置 cookie，確保一定回到未登入狀態（導回登入頁）
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )


    return {"ok": True}


# ===== 登入 =====
@router.post("/login")
def login(
    body: LoginIn,
    request: Request,
    response: Response,
    db: OrmSession = Depends(get_db),
):
    # 1. 檢查 Email 格式
    try:
        EMAIL_ADAPTER.validate_python(body.email)
    except Exception:
        _raise_400({"email": "Email 格式不正確。"})

    # 2. 驗證帳號密碼
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.password_hash):
        _raise_400({"credentials": "帳號或密碼錯誤。"})

    # 3. 尚未完成 Email 驗證：建立 session + 嘗試重寄驗證信 + 回 400
    if not user.is_active:
        # 3-1 建立「半登入」的 session，讓 /me 可以讀到 email
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
        # 尚未完成 Email 驗證：建立 session，允許「受限登入」
        # 注意：不要在 login 時自動寄信，寄信由使用者點擊「尚未驗證/重新寄送」觸發

        # 3-ㄉ 不丟錯：允許登入，但前端會依 /me 的 is_active=false 進入「受限模式」
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



# ===== 登出 =====

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

    # 清除瀏覽器端 Cookie
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value="",
        max_age=0,
        expires=0,
        httponly=True,
        secure=True,
        samesite="Lax",
        path="/",
    )
    # 204 No Content
    return
