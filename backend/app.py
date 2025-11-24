# backend/app.py
import os
from ipaddress import ip_address, ip_network
from datetime import datetime, timedelta, timezone
from uuid import uuid4, UUID

from fastapi import FastAPI, Request, Response, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr, constr, TypeAdapter

from api.chat import router as chat_router
from api.debug import router as debug_router

from backend.db import SessionLocal
from backend.models import User, Session
from backend.security import (
    hash_password,
    verify_password,
)

# ===== App & CORS =====
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://pcbuild.redfiretw.xyz"],  # 開發期可改為 ["*"]
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== 只允許內網查看 /docs /openapi.json =====
_PRIVATE_NETS = [
    ip_network("127.0.0.0/8"),
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("::1/128"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
]


class _DocsGateMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        p = request.url.path
        if p in ("/docs", "/redoc", "/openapi.json"):
            # 經 Cloudflare Tunnel 進來會帶 CF-Connecting-IP => 視為外網，直接 404
            if request.headers.get("CF-Connecting-IP"):
                return Response(status_code=404)
            # 內網直連則檢查來源 IP
            host = request.client.host or ""
            try:
                ip = ip_address(host)
                if not any(ip in n for n in _PRIVATE_NETS):
                    return Response(status_code=404)
            except ValueError:
                return Response(status_code=404)
        return await call_next(request)


app.add_middleware(_DocsGateMiddleware)
app.include_router(chat_router)
app.include_router(debug_router)

EMAIL_ADAPTER = TypeAdapter(EmailStr)
SESSION_COOKIE_NAME = "pcbuild_session"
SESSION_EXPIRES_MINUTES = int(os.getenv("SESSION_EXPIRES_MINUTES", "120"))  # 例如 120 分鐘


# ===== Auth 用的 Pydantic 模型 =====
class RegisterIn(BaseModel):
    email: constr(strip_whitespace=True, min_length=3, max_length=50)
    username: constr(strip_whitespace=True, min_length=3, max_length=50)
    password: constr(min_length=8, max_length=128)


class RegisterOut(BaseModel):
    id: int
    email: EmailStr
    username: str
    created_at: datetime


class LoginIn(BaseModel):
    email: constr(strip_whitespace=True, min_length=3, max_length=50)
    password: constr(min_length=8, max_length=128)


class MeOut(BaseModel):
    id: int
    email: EmailStr
    username: str
    is_admin: bool
    created_at: datetime


# ===== DB Session 依賴 =====
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """
    從 HttpOnly Cookie (pcbuild_session) 取得目前登入的使用者。
    若 Cookie 不存在、session 無效或過期，一律回傳 401。
    """
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未登入或憑證已失效",
        )

    try:
        session_id = UUID(session_token)
    except ValueError:
        # Cookie 內容不是合法 UUID，視為無效
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未登入或憑證已失效",
        )

    now = datetime.now(timezone.utc)

    session = (
        db.query(Session)
        .filter(
            Session.id == session_id,
            Session.revoked == False,
            Session.expires_at > now,
        )
        .first()
    )

    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未登入或憑證已失效",
        )

    user = (
        db.query(User)
        .filter(User.id == session.user_id)
        .first()
    )

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未登入或憑證已失效",
        )

    return user

@app.get("/api/auth/me", response_model=MeOut)
def get_me(current_user: User = Depends(get_current_user)):
    """
    回傳目前登入的使用者基本資訊。
    若未登入或 session 無效，會被 get_current_user 擋掉回 401。
    """
    return MeOut(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        is_admin=current_user.is_admin,
        created_at=current_user.created_at,
    )


# ===== 註冊 API =====
@app.post("/api/auth/register", response_model=RegisterOut)
def register(body: RegisterIn, db: Session = Depends(get_db)):
    # 先檢查 Email 格式（避免 Pydantic 回 422）
    try:
        EMAIL_ADAPTER.validate_python(body.email)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"errors": {"email": "Email 格式不正確。"}},
        )
    
    # 檢查 Email / 使用者名稱是否已存在（一次收集所有欄位錯誤）
    errors: dict[str, str] = {}

    if db.query(User).filter(User.email == body.email).first():
        errors["email"] = "Email 已被註冊。"

    if db.query(User).filter(User.username == body.username).first():
        errors["username"] = "使用者名稱已被註冊。"

    if errors:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"errors": errors},
        )

    # 使用 Argon2id 雜湊密碼
    hashed = hash_password(body.password)

    user = User(
        email=body.email,
        username=body.username,
        password_hash=hashed,
        is_active=True,
        is_admin=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return RegisterOut(
        id=user.id,
        email=user.email,
        username=user.username,
        created_at=user.created_at,
    )


# ===== 登入 API（只接受 email + password） =====
@app.post("/api/auth/login")
def login(
    body: LoginIn,
    response: Response,
    db: Session = Depends(get_db),
):
    # 先檢查 Email 格式
    try:
        EMAIL_ADAPTER.validate_python(body.email)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"errors": {"email": "Email 格式不正確。"}},
        )
    # 1. 驗證帳號密碼
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"errors": {"credentials": "帳號或密碼錯誤。"}},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"errors": {"account": "帳號已停用，請聯絡管理者。"}},
        )

    # 2. 建立新的 session 紀錄
    now = datetime.now(timezone.utc)
    ttl = timedelta(minutes=SESSION_EXPIRES_MINUTES)
    expires_at = now + ttl

    session = Session(
        id=uuid4(),
        user_id=user.id,
        expires_at=expires_at,
    )
    db.add(session)
    db.commit()

    # 3. 設定 HttpOnly + Secure + SameSite=Lax Cookie
    #    max_age 使用秒數，與資料庫中的 expires_at 對應
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=str(session.id),
        max_age=int(ttl.total_seconds()),
        httponly=True,
        secure=True,      # 正式環境使用 HTTPS（例如經 Cloudflare Tunnel）
        samesite="Lax",
        path="/",
    )
    return {"ok": True}


@app.post("/api/auth/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
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
                db.query(Session)
                .filter(Session.id == session_id, Session.revoked == False)
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


# ===== 靜態網站：最後才 mount，避免吃掉 API 路由 =====
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(ROOT_DIR, "web")
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="site")
