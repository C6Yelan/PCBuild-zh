# backend/api/auth.py
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4, UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session as OrmSession
from pydantic import EmailStr, TypeAdapter

from backend.api.deps import get_db
from backend.models import User, Session as SessionModel
from backend.schemas.auth import RegisterIn, RegisterOut, LoginIn, MeOut
from backend.security import hash_password, verify_password
from backend.services.auth.email_verification import (
    send_signup_verification_for_user,
    verify_signup_token_and_activate_user,
    InvalidOrExpiredTokenError,
    resend_signup_verification_for_email,
    VerificationEmailRateLimitedError,
)
router = APIRouter(prefix="/api/auth", tags=["auth"])

EMAIL_ADAPTER = TypeAdapter(EmailStr)
SESSION_COOKIE_NAME = "pcbuild_session"
SESSION_EXPIRES_MINUTES = int(os.getenv("SESSION_EXPIRES_MINUTES", "120"))


# ===== 共用錯誤拋出工具 =====

def _raise_400(errors: dict[str, str]) -> None:
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"errors": errors},
    )


# ===== 目前登入使用者依賴 =====

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
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未登入或憑證已失效",
        )

    return user


# ===== 取得目前登入使用者 =====

@router.get("/me", response_model=MeOut)
def get_me(current_user: User = Depends(get_current_user)) -> MeOut:
    return MeOut(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        is_admin=current_user.is_admin,
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
    db: OrmSession = Depends(get_db),
):
    """
    註冊 email 驗證入口。

    - 驗證 token，啟用帳號
    - 驗證成功後自動建立 session
    - 設定 HttpOnly Cookie，然後 302 導回首頁 (/)
    """
    try:
        user = verify_signup_token_and_activate_user(
            db=db,
            public_token=token,
        )
    except InvalidOrExpiredTokenError:
        return RedirectResponse(
            url="/verify-email-failed",
            status_code=status.HTTP_302_FOUND,
        )

    # === 建立新的 session（沿用 login 的邏輯） ===
    now = datetime.now(timezone.utc)
    ttl = timedelta(minutes=SESSION_EXPIRES_MINUTES)
    expires_at = now + ttl

    session = SessionModel(
        id=uuid4(),
        user_id=user.id,
        expires_at=expires_at,
    )
    db.add(session)
    db.commit()

    # === 建立 RedirectResponse，並在上面設定 Cookie ===
    resp = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    resp.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=str(session.id),
        max_age=int(ttl.total_seconds()),
        httponly=True,
        secure=True,
        samesite="Lax",
        path="/",
    )

    return resp


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
        # 過於頻繁，回傳 429 並提示
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"errors": {"email": "驗證信寄送太頻繁，請在 1 分鐘後再試。"}},
        )

    # 3. 一律回傳成功（不暴露帳號是否存在或是否已驗證）
    return {"ok": True}


# ===== 登入 =====

@router.post("/login")
def login(
    body: LoginIn,
    request: Request,          # ← 新增：需要 Request 來組驗證網址
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

    # 2-1. 帳號存在但尚未完成 Email 驗證：
    #      先嘗試根據最近一筆 signup token 做 1 分鐘冷卻的重寄信，
    #      被 rate limit 則靜默忽略，最後一律回同一個錯誤訊息。
    if not user.is_active:
        try:
            # 內部會：
            # - 用 user.id 查出最新一筆 purpose="signup" 的 token
            # - 若 token 建立時間超過 1 分鐘，就建立新 token 並寄驗證信
            # - 若不到 1 分鐘，丟出 VerificationEmailRateLimitedError
            resend_signup_verification_for_email(
                db=db,
                email=user.email,
                request=request,
            )
        except VerificationEmailRateLimitedError:
            # 冷卻中：這裡不再往外丟錯，只是不重寄信
            pass

        _raise_400({"email": "Email 尚未驗證，請先完成信箱驗證。"})

    # 3. 建立新的 session 紀錄（使用 ORM）
    now = datetime.now(timezone.utc)
    ttl = timedelta(minutes=SESSION_EXPIRES_MINUTES)
    expires_at = now + ttl

    session = SessionModel(
        id=uuid4(),
        user_id=user.id,
        expires_at=expires_at,
    )
    db.add(session)
    db.commit()

    # 4. 設定 HttpOnly + Secure + SameSite=Lax Cookie
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
