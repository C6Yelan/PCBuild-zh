# backend/app.py
from typing import List, Literal
import os
from ipaddress import ip_address, ip_network
from datetime import datetime

from fastapi import FastAPI, Request, Response, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
from pydantic import BaseModel, EmailStr, constr
from google import genai

from backend.db import SessionLocal
from backend.models import User
from backend.security import (
    hash_password,
    verify_password,
    create_access_token,
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

# ===== AI 客戶端 =====
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))
SYSTEM_PROMPT = "你是電腦組裝顧問，所有回覆一律使用繁體中文。"


# ===== 多輪對話資料結構 =====
class Turn(BaseModel):
    role: Literal["user", "ai"]
    content: str


class ChatIn(BaseModel):
    message: str
    history: List[Turn] = []


class ChatOut(BaseModel):
    reply: str


@app.post("/api/chat", response_model=ChatOut)
def chat(body: ChatIn):
    # 組上下文（只取最近 N 筆，避免超長）
    N = 8

    def _fmt(t: Turn):
        who = "使用者" if t.role == "user" else "AI"
        return f"{who}：{t.content}"

    history_txt = "\n".join(_fmt(t) for t in body.history[-N:])

    prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"以下是先前對話紀錄（舊→新，最多{N}則）：\n{history_txt}\n\n"
        f"現在的使用者訊息：{body.message}\n"
        f"請在理解脈絡後以繁體中文回答。"
    )

    resp = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
    )
    return {"reply": (resp.text or "").strip()}


# ===== Auth 用的 Pydantic 模型 =====
class RegisterIn(BaseModel):
    email: EmailStr
    username: constr(min_length=3, max_length=50)
    password: constr(min_length=8, max_length=128)


class RegisterOut(BaseModel):
    id: int
    email: EmailStr
    username: str
    created_at: datetime


class LoginIn(BaseModel):
    # 登入只用 email + password
    email: EmailStr
    password: constr(min_length=8, max_length=128)


class LoginOut(BaseModel):
    access_token: str
    token_type: Literal["bearer"]


# ===== DB Session 依賴 =====
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/debug/db")
def debug_db(db: Session = Depends(get_db)):
    result = db.execute(text("SELECT 1")).scalar_one()
    return {"db_ok": result == 1}


# ===== 註冊 API =====
@app.post("/api/auth/register", response_model=RegisterOut)
def register(body: RegisterIn, db: Session = Depends(get_db)):
    # 檢查 email 是否已存在
    existing = db.query(User).filter(User.email == body.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email 已被註冊",
        )

    # 檢查 username 是否已存在
    existing_username = db.query(User).filter(User.username == body.username).first()
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="使用者名稱已被註冊",
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
@app.post("/api/auth/login", response_model=LoginOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()

    # 不回傳太多細節，避免暴露帳號是否存在
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="帳號或密碼錯誤",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="帳號已停用，請聯絡管理者",
        )

    token = create_access_token(user_id=user.id)
    return LoginOut(access_token=token, token_type="bearer")


# ===== 靜態網站：最後才 mount，避免吃掉 API 路由 =====
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(ROOT_DIR, "web")
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="site")
