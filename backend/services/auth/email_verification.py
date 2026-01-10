# backend/services/auth/email_verification.py
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from enum import Enum

from argon2 import PasswordHasher, exceptions as argon2_exceptions
from sqlalchemy.orm import Session

from backend.models import User, EmailVerificationToken
from backend.services.email.client import (
    send_signup_verification_email,
    send_password_reset_email,
)

from fastapi import Request


class VerificationPurpose(str, Enum):
    """驗證碼用途（目前使用 SIGNUP / PASSWORD_RESET）。"""
    SIGNUP = "signup"
    PASSWORD_RESET = "password_reset"
    # 未來要做登入驗證可新增：
    # LOGIN = "login"


# 各用途預設有效時間（分鐘）
# 後面計算 expires_at 一律直接用這裡的分鐘數。
DEFAULT_LIFETIME_MINUTES: dict[VerificationPurpose, int] = {
    # 註冊驗證：24 小時
    VerificationPurpose.SIGNUP: 24 * 60,
    # 忘記密碼：20 分鐘
    VerificationPurpose.PASSWORD_RESET: 20,
}

# 各用途重新寄送驗證信 / 重設密碼信的最小間隔（分鐘）
# 之後 rate limit 判斷一律從這裡取值。
RESEND_MIN_INTERVAL_MINUTES: dict[VerificationPurpose, int] = {
    # 註冊驗證信：1 分鐘冷卻
    VerificationPurpose.SIGNUP: 1,
    # 忘記密碼信：1 分鐘冷卻（之後若要調整再改這裡即可）
    VerificationPurpose.PASSWORD_RESET: 1,
}


class VerificationEmailRateLimitedError(Exception):
    """在允許時間間隔內過度頻繁要求重新寄送驗證信時拋出。"""


# 專用 Argon2id hasher，用來雜湊「驗證碼」，與密碼雜湊邏輯隔離
_token_hasher = PasswordHasher()


class TokenState(str, Enum):
    INVALID = "invalid"           # 格式錯、找不到、secret 不匹配
    EXPIRED = "expired"           # 超過 expires_at
    USED = "used"                 # token 本身已被消費
    SUPERSEDED = "superseded"     # 被更新的 token 取代（例如只允許最新）
    ALREADY_VERIFIED = "already_verified"  # SIGNUP：帳號已啟用，連結自然失效


class InvalidOrExpiredTokenError(Exception):
    """token 驗證失敗（前端統一顯示已失效；後端用 state 區分原因）。"""

    def __init__(self, message: str = "驗證連結已失效。", *, state: TokenState = TokenState.INVALID):
        super().__init__(message)
        self.state = state


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


def _resolve_lifetime_minutes(
    purpose: VerificationPurpose,
    override_minutes: int | None,
) -> int:
    """
    依用途取得此類驗證碼的有效時間（以分鐘為單位）。

    - 若有傳入 override_minutes，優先採用傳入值
    - 否則使用 DEFAULT_LIFETIME_MINUTES[purpose]
    """
    if override_minutes is not None:
        return override_minutes
    return DEFAULT_LIFETIME_MINUTES[purpose]



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

#== 發行驗證碼 ===
def issue_verification_token(
    db: Session,
    user: User,
    *,
    purpose: VerificationPurpose,
    expires_in_minutes: int | None = None,
) -> str:
    """
    發行驗證碼（通用版本）。

    - 依 purpose 決定存入的用途欄位
    - 支援自訂 expires_in_minutes，未指定時使用 DEFAULT_LIFETIME_MINUTES
    - 回傳給使用者的 public token 格式為 "<id>.<secret>"
    """
    lifetime_minutes = _resolve_lifetime_minutes(purpose, expires_in_minutes)

    secret = secrets.token_urlsafe(32)
    token_hash = _hash_token(secret)
    now = _utcnow()
    expires_at = now + timedelta(minutes=lifetime_minutes)

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

#== 忘記密碼專用封裝（使用通用流程） ===
def issue_password_reset_token_for_user(
    db: Session,
    user: User,
    *,
    min_interval_minutes: int | None = None,
) -> str:
    """
    忘記密碼流程專用：為指定使用者發行「重設密碼」 token。

    設計重點：
    - 依 PASSWORD_RESET 的冷卻時間做簡單 rate limit。
    - latest-only + SUPERSEDED” 來失效舊 token（由驗證階段判斷）。
    - 回傳 public token（給上層組合 reset URL 使用）。
    """
    now = _utcnow()

    # 1) 取得冷卻時間（分鐘）
    if min_interval_minutes is None:
        min_interval_minutes = RESEND_MIN_INTERVAL_MINUTES[
            VerificationPurpose.PASSWORD_RESET
        ]

    # 2) 檢查最近一次 PASSWORD_RESET token 的建立時間
    latest = _get_latest_token_for_user(
        db=db,
        user_id=user.id,
        purpose=VerificationPurpose.PASSWORD_RESET,
    )

    if latest is not None:
        if latest.created_at + timedelta(minutes=min_interval_minutes) > now:
            # 在冷卻期間內就拒絕發新 token
            raise VerificationEmailRateLimitedError(
                "重設密碼請求太頻繁，請稍後再試。"
            )

    # 4) 發行新的 PASSWORD_RESET token
    #    有效時間會由 DEFAULT_LIFETIME_MINUTES[VerificationPurpose.PASSWORD_RESET]
    #    決定，不需要在這裡覆寫。
    public_token = issue_verification_token(
        db=db,
        user=user,
        purpose=VerificationPurpose.PASSWORD_RESET,
    )

    return public_token

#== 驗證並消費驗證碼 ===
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
        raise InvalidOrExpiredTokenError("找不到對應的驗證資訊。", state=TokenState.INVALID)

    # 1) 載入 user
    user = db.query(User).filter(User.id == token.user_id).first()
    if user is None:
        raise InvalidOrExpiredTokenError("找不到對應的驗證資訊。", state=TokenState.INVALID)

    # 2) 驗證 secret 是否匹配 token_hash（避免只靠 token_id 就可用）
    if not _verify_token(secret, token.token_hash):
        raise InvalidOrExpiredTokenError("找不到對應的驗證資訊。", state=TokenState.INVALID)

    now = _utcnow()

    # 3) 驗證是否過期
    if token.expires_at < now:
        raise InvalidOrExpiredTokenError(state=TokenState.EXPIRED)

    # 4) 依用途驗證其他條件
    if expected_purpose == VerificationPurpose.PASSWORD_RESET:
        # 先判斷是否為最新（讓非最新的就算 is_used=True 也回 SUPERSEDED）
        latest = _get_latest_token_for_user(
            db=db,
            user_id=user.id,
            purpose=VerificationPurpose.PASSWORD_RESET,
        )
        if latest is not None and latest.id != token.id:
            raise InvalidOrExpiredTokenError(state=TokenState.SUPERSEDED)

        # 再判斷是否已使用（此時只會影響「最新那筆已被消費」的情境）
        if token.is_used:
            raise InvalidOrExpiredTokenError(state=TokenState.USED)

    else:
        # SIGNUP（或未來其他用途）：已使用優先
        if token.is_used:
            raise InvalidOrExpiredTokenError(state=TokenState.USED)

        if expected_purpose == VerificationPurpose.SIGNUP and user.is_active:
            raise InvalidOrExpiredTokenError(state=TokenState.ALREADY_VERIFIED)

    return token, user


def load_valid_token_and_user(
    db: Session,
    public_token: str,
    *,
    expected_purpose: VerificationPurpose,
) -> tuple[EmailVerificationToken, User]:
    """
    公開的 read-only 驗證介面：只做載入與檢查，不改寫 token，也不 commit。
    統一由本模組內部 private helper 實作細節，避免其他模組直接依賴底層函式。
    """
    return _load_valid_token_and_user(
        db=db,
        public_token=public_token,
        expected_purpose=expected_purpose,
    )


#== 通用消費驗證碼流程 ===
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
    expires_in_minutes: int | None = None,
) -> str:
    """
    註冊流程專用：發行 email 驗證碼。

    未來要新增登入驗證碼、忘記密碼驗證碼時，只需呼叫
    issue_verification_token(...) 並指定對應的 purpose 即可。
    """
    return issue_verification_token(
        db=db,
        user=user,
        purpose=VerificationPurpose.SIGNUP,
        expires_in_minutes=expires_in_minutes,
    )


def verify_signup_token_and_activate_user(
    db: Session,
    public_token: str,
) -> User:
    """
    註冊流程專用：驗證 token + 啟用帳號。

    - 使用通用 consume_verification_token(...) 確認 token
    - 啟用 user.is_active
    - 消費本次 token、啟用 user；其他舊 token 不批次標 used，改由驗證階段視為已失效（ALREADY_VERIFIED）
    - 由此函式一次 commit，確保變更在同一個 transaction 中完成
    """

    # 這一步會：
    # - 驗證 public_token（比對雜湊、用途、未過期、未使用等）
    # - 標記「這一筆」 token 為已使用
    user, token = consume_verification_token(
        db=db,
        public_token=public_token,
        purpose=VerificationPurpose.SIGNUP,
    )

    # 啟用帳號
    user.is_active = True

    # user 狀態變更 + token 失效一起 commit
    db.add(user)
    db.commit()
    db.refresh(user)

    return user

#== 寄送註冊驗證信 ===
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

#== 重新寄送註冊驗證信（有冷卻控管） ===
def resend_signup_verification_for_email(
    db: Session,
    email: str,
    *,
    request: Request,
) -> None:
    """
    依 Email 重新寄送註冊驗證信。

    設計重點：
    - 若使用者不存在或已啟用 (is_active=True)，靜默返回，不暴露帳號是否存在。
    - 若最近一次寄送在該用途的最小間隔時間內，拋出 VerificationEmailRateLimitedError，
      交由上層決定回應內容（例如「請稍後再試」）。
    - 其他情況則重新發一封，底層仍使用 send_signup_verification_for_user。
    """
    # 依用途取得冷卻時間（分鐘）
    min_interval_minutes = RESEND_MIN_INTERVAL_MINUTES[VerificationPurpose.SIGNUP]

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

#== 「忘記密碼」專用封裝（使用通用流程） ===
def send_password_reset_for_user(
    db: Session,
    user: User,
    *,
    request: Request,
) -> str:
    """
    忘記密碼流程專用：為指定使用者發行重設密碼 token 並寄出 Email。

    設計重點：
    - 適用於帳號存在即可寄送重設密碼信的情境（不論帳號是否啟用皆可寄送）
    - 依 PASSWORD_RESET 的設定做冷卻控管（分鐘）
    - 僅最新 token 有效；舊 token 由驗證階段判定為 SUPERSEDED
    - 由這層組合 reset URL，並呼叫 send_password_reset_email 寄信
    """

    now = _utcnow()

    # 2) 取得重設密碼的冷卻時間（分鐘）
    min_interval_minutes = RESEND_MIN_INTERVAL_MINUTES[
        VerificationPurpose.PASSWORD_RESET
    ]

    # 3) 檢查最近一次 PASSWORD_RESET token 建立時間（rate limit）
    latest = _get_latest_token_for_user(
        db=db,
        user_id=user.id,
        purpose=VerificationPurpose.PASSWORD_RESET,
    )

    if latest is not None:
        if latest.created_at + timedelta(minutes=min_interval_minutes) > now:
            # 在冷卻期間內就拒絕發新 token
            raise VerificationEmailRateLimitedError(
                "重設密碼請求太頻繁，請稍後再試。"
            )

    # 5) 發行新的 PASSWORD_RESET token（有效時間已在 DEFAULT_LIFETIME_MINUTES 中設定為 20 分鐘）
    public_token = issue_verification_token(
        db=db,
        user=user,
        purpose=VerificationPurpose.PASSWORD_RESET,
    )

    # 6) 產生重設密碼頁面的路由網址
    #    之後會在 auth router 中實作：
    #      @router.get("/reset-password/{token}", name="reset_password")
    reset_url = request.url_for("reset_password", token=public_token)

    # 7) 寄出重設密碼 Email（版型與註冊驗證信相同）
    send_password_reset_email(
        to_email=user.email,
        reset_url=str(reset_url),
    )

    # 回傳網址方便上層做記錄或除錯（必要時可忽略）
    return str(reset_url)
