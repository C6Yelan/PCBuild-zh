# backend/security.py
import os
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from jose import jwt, JWTError

# ===== 密碼雜湊（Argon2id） =====

_ph = PasswordHasher()


def hash_password(plain_password: str) -> str:
    """將純文字密碼做 Argon2id 雜湊，回傳可儲存到資料庫的字串。"""
    return _ph.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """驗證登入時輸入的密碼是否與資料庫中的雜湊相符。"""
    try:
        return _ph.verify(password_hash, plain_password)
    except (VerifyMismatchError, VerificationError):
        return False


# ===== JWT 設定（正式環境用） =====

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    # 正式環境：如果沒設環境變數就直接讓服務啟動失敗
    raise RuntimeError("JWT_SECRET_KEY is not set in environment")

JWT_ALGORITHM = "HS256"
JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "60"))


def create_access_token(user_id: int) -> str:
    """
    產生 access token。
    payload 只放使用者 id（sub），有效時間由 JWT_EXPIRES_MINUTES 控制。
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXPIRES_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_access_token(token: str) -> int | None:
    """
    驗證 access token。
    驗證成功回傳 user_id（int），失敗回傳 None。
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        sub = payload.get("sub")
        return int(sub) if sub is not None else None
    except (JWTError, ValueError, TypeError):
        return None
