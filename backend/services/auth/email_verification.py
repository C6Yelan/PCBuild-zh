# backend/services/auth/email_verification.py

# 1) 保留你拆分後的對外函式（facade）
from backend.services.auth.email_tokens import (
    issue_verification_token,
    issue_password_reset_token_for_user,
    load_valid_token_and_user,
    consume_verification_token,
)
from backend.services.auth.signup_verification import (
    issue_signup_verification_token,
    verify_signup_token_and_activate_user,
    send_signup_verification_for_user,
    resend_signup_verification_for_email,
)
from backend.services.auth.password_reset import send_password_reset_for_user

# 2) 追加：補回舊版 verification.py 會 import 的「型別/例外/常數」
from backend.services.auth.verification.core import (
    VerificationPurpose,
    DEFAULT_LIFETIME_MINUTES,
    RESEND_MIN_INTERVAL_MINUTES,
    VerificationEmailRateLimitedError,
    TokenState,
    InvalidOrExpiredTokenError,
)

__all__ = [
    # functions
    "issue_verification_token",
    "issue_password_reset_token_for_user",
    "load_valid_token_and_user",
    "consume_verification_token",
    "issue_signup_verification_token",
    "verify_signup_token_and_activate_user",
    "send_signup_verification_for_user",
    "resend_signup_verification_for_email",
    "send_password_reset_for_user",
    # re-exported types/errors/constants (backward compatible)
    "VerificationPurpose",
    "DEFAULT_LIFETIME_MINUTES",
    "RESEND_MIN_INTERVAL_MINUTES",
    "VerificationEmailRateLimitedError",
    "TokenState",
    "InvalidOrExpiredTokenError",
]
