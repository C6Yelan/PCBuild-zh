# backend/services/auth/email_verification.py
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from enum import Enum

from argon2 import PasswordHasher, exceptions as argon2_exceptions
from sqlalchemy.orm import Session

from backend.models import User, EmailVerificationToken
from backend.services.email.client import send_signup_verification_email

from fastapi import Request


class VerificationPurpose(str, Enum):
    """驗證碼用途（目前只用到 SIGNUP，未來可擴充 LOGIN 等）。"""
    SIGNUP = "signup"
    # 未來要做登入驗證可新增：
    # LOGIN = "login"


# 各用途預設有效時間（小時）
DEFAULT_LIFETIME_HOURS: dict[VerificationPurpose, int] = {
    VerificationPurpose.SIGNUP: 24,
}

# 重新寄送驗證信的最小間隔（分鐘）
RESEND_MIN_INTERVAL_MINUTES = 1


class VerificationEmailRateLimitedError(Exception):
    """在允許時間間隔內過度頻繁要求重新寄送驗證信時拋出。"""


# 專用 Argon2id hasher，用來雜湊「驗證碼」，與密碼雜湊邏輯隔離
_token_hasher = PasswordHasher()


class InvalidOrExpiredTokenError(Exception):
    """驗證信 token 無效或已過期時拋出的錯誤。"""


# === 共用小工具 ===


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _hash_token(secret: str) -> str:
    return _token_hasher.hash(secret)


def _verify_token(secret: str, token_hash: str) -> bool:
    try:
        return _token_hasher.verify(token_hash, secret)
    except (
        argon2_exceptions.VerifyMismatchError,
        argon2_exceptions.VerificationError,
    ):
        return False
    except Exception:
        return False


def _split_public_token(public_token: str) -> tuple[int, str]:
    """
    將使用者收到的 token 拆成 (id, secret)。

    格式: "<id>.<secret>"
    - id: email_verification_tokens.id
    - secret: 真正隨機字串，只存雜湊後版本在資料庫
    """
    try:
        id_str, secret = public_token.split(".", 1)
        token_id = int(id_str)
    except (ValueError, AttributeError):
        raise InvalidOrExpiredTokenError("Token 格式不正確。")

    if not secret:
        raise InvalidOrExpiredTokenError("Token 格式不正確。")

    return token_id, secret


def _resolve_lifetime_hours(
    purpose: VerificationPurpose,
    override_hours: int | None,
) -> int:
    if override_hours is not None:
        return override_hours
    return DEFAULT_LIFETIME_HOURS[purpose]


def _get_latest_token_for_user(
    db: Session,
    user_id: int,
    *,
    purpose: VerificationPurpose,
) -> EmailVerificationToken | None:
    """取得某個使用者在指定用途下最新的一筆驗證 token。"""
    return (
        db.query(EmailVerificationToken)
        .filter(
            EmailVerificationToken.user_id == user_id,
            EmailVerificationToken.purpose == purpose.value,
        )
        .order_by(EmailVerificationToken.created_at.desc())
        .first()
    )


# === 通用發行 / 驗證流程（未綁定「註冊」或「登入」） ===


def issue_verification_token(
    db: Session,
    user: User,
    *,
    purpose: VerificationPurpose,
    expires_in_hours: int | None = None,
) -> str:
    """
    發行驗證碼（通用版本）。

    - 依 purpose 決定存入的用途欄位
    - 支援自訂 expires_in_hours，未指定時使用 DEFAULT_LIFETIME_HOURS
    - 回傳給使用者的 public token 格式為 "<id>.<secret>"
    """
    lifetime_hours = _resolve_lifetime_hours(purpose, expires_in_hours)

    secret = secrets.token_urlsafe(32)
    token_hash = _hash_token(secret)

    now = _utcnow()
    expires_at = now + timedelta(hours=lifetime_hours)

    token = EmailVerificationToken(
        user_id=user.id,
        token_hash=token_hash,
        purpose=purpose.value,
        is_used=False,
        created_at=now,
        expires_at=expires_at,
    )

    db.add(token)
    db.commit()
    db.refresh(token)

    public_token = f"{token.id}.{secret}"
    return public_token


def _load_valid_token_and_user(
    db: Session,
    public_token: str,
    *,
    expected_purpose: VerificationPurpose,
) -> tuple[EmailVerificationToken, User]:
    """
    依 public_token 載入並驗證 token + user，但「不改寫也不 commit」。

    若 token 無效 / 過期 / hash 不符 / user 不存在，會拋出 InvalidOrExpiredTokenError。
    """
    token_id, secret = _split_public_token(public_token)

    token = (
        db.query(EmailVerificationToken)
        .filter(
            EmailVerificationToken.id == token_id,
            EmailVerificationToken.purpose == expected_purpose.value,
        )
        .first()
    )

    if token is None:
        raise InvalidOrExpiredTokenError("找不到對應的驗證資訊。")

    now = _utcnow()
    if token.is_used or token.expires_at < now:
        raise InvalidOrExpiredTokenError("驗證連結已使用或已過期。")

    if not _verify_token(secret, token.token_hash):
        raise InvalidOrExpiredTokenError("驗證碼不正確。")

    user = db.query(User).filter(User.id == token.user_id).first()
    if user is None:
        raise InvalidOrExpiredTokenError("找不到對應的使用者。")

    return token, user


def consume_verification_token(
    db: Session,
    public_token: str,
    *,
    purpose: VerificationPurpose,
) -> tuple[User, EmailVerificationToken]:
    """
    通用「消費 token」流程：

    - 驗證 token 是否存在、未過期、hash 正確、用途正確
    - 將 token.is_used 設為 True（但不在這裡 commit）
    - 回傳 (user, token)，讓上層決定後續要對 user 做什麼修改

    由呼叫端負責最後的 db.commit()，方便將 token 狀態更新與
    其他業務邏輯（例如啟用帳號、建立登入 session）放在同一個 transaction 裡。
    """
    token, user = _load_valid_token_and_user(
        db,
        public_token,
        expected_purpose=purpose,
    )

    token.is_used = True
    return user, token


# === 「註冊驗證」專用封裝（使用通用流程） ===


def issue_signup_verification_token(
    db: Session,
    user: User,
    *,
    expires_in_hours: int | None = None,
) -> str:
    """
    註冊流程專用：發行 email 驗證碼。

    未來要新增登入驗證碼時，只需呼叫 issue_verification_token(...)
    並指定 purpose=VerificationPurpose.LOGIN 即可，無須重新實作底層流程。
    """
    return issue_verification_token(
        db=db,
        user=user,
        purpose=VerificationPurpose.SIGNUP,
        expires_in_hours=expires_in_hours,
    )


def verify_signup_token_and_activate_user(
    db: Session,
    public_token: str,
) -> User:
    """
    註冊流程專用：驗證 token + 啟用帳號。

    - 使用通用 consume_verification_token(...) 確認 token
    - 標記 token 已使用
    - 將 user.is_active 設為 True
    - 由此函式一次 commit，確保兩者同一個 transaction
    """
    user, token = consume_verification_token(
        db=db,
        public_token=public_token,
        purpose=VerificationPurpose.SIGNUP,
    )

    user.is_active = True

    db.add(user)
    db.add(token)
    db.commit()
    db.refresh(user)

    return user

def send_signup_verification_for_user(
    db: Session,
    user: User,
    *,
    request: Request,
) -> str:
    """
    高階封裝：對指定使用者產生註冊用驗證碼並寄出驗證信。

    - issue_signup_verification_token(...) 建立一筆 token 紀錄
    - 使用 request.url_for("verify_email", token=...) 產生完整驗證網址
    - 呼叫 send_signup_verification_email(...) 寄出信件
    - 回傳 verify_url（方便上層在 debug / log 中記錄）

    要配合一個名為 "verify_email" 的路由，例如：
        @router.get("/verify-email/{token}", name="verify_email")
    """
    # 1) 產生註冊用驗證 token，寫入 email_verification_tokens
    public_token = issue_signup_verification_token(db=db, user=user)

    # 2) 使用 FastAPI 的 url_for 產生完整網址
    #    假設在 auth router 裡有：
    #        @router.get("/verify-email/{token}", name="verify_email")
    verify_url = request.url_for("verify_email", token=public_token)

    # 3) 寄出驗證信
    send_signup_verification_email(
        to_email=user.email,
        verify_url=str(verify_url),
    )

    return str(verify_url)


def resend_signup_verification_for_email(
    db: Session,
    email: str,
    *,
    request: Request,
    min_interval_minutes: int = RESEND_MIN_INTERVAL_MINUTES,
) -> None:
    """
    依 Email 重新寄送註冊驗證信。

    設計重點：
    - 若使用者不存在或已啟用 (is_active=True)，靜默返回，不暴露帳號是否存在。
    - 若最近一次寄送在 min_interval_minutes 以內，拋出 VerificationEmailRateLimitedError，
      交由上層決定回應內容（例如「請稍後再試」）。
    - 其他情況則重新發一封，底層仍使用 send_signup_verification_for_user。
    """
    # 1) 找出該 Email 的使用者
    user = db.query(User).filter(User.email == email).first()
    if user is None or user.is_active:
        # 為避免帳號存在性被探測，這裡直接靜默返回
        return

    # 2) 檢查最近一次寄送時間，做簡單的 rate limit
    latest = _get_latest_token_for_user(
        db=db,
        user_id=user.id,
        purpose=VerificationPurpose.SIGNUP,
    )

    if latest is not None:
        now = _utcnow()
        if latest.created_at + timedelta(minutes=min_interval_minutes) > now:
            raise VerificationEmailRateLimitedError(
                "驗證信寄送太頻繁，請在 1 分鐘後再試。"
            )

    # 3) 寄出新的驗證信（內部會建立新的 token）
    send_signup_verification_for_user(
        db=db,
        user=user,
        request=request,
    )
