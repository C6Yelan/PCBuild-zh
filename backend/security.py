# backend/security.py
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

# Argon2id：目前主流且安全性高的密碼雜湊演算法
_ph = PasswordHasher()


def hash_password(plain_password: str) -> str:
    """
    將使用者輸入的純文字密碼做 Argon2id 雜湊，回傳可儲存到資料庫的字串。
    """
    return _ph.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """
    驗證登入時輸入的密碼是否與資料庫中的雜湊相符。
    """
    try:
        return _ph.verify(password_hash, plain_password)
    except VerifyMismatchError:
        # 密碼錯誤
        return False
    except VerificationError:
        # 雜湊格式有問題等其他錯誤，一律當作驗證失敗
        return False
