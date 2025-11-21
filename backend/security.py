# backend/security.py
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

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