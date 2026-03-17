# backend/services/auth/workflows/signup_verification.py
from __future__ import annotations

from datetime import timedelta

from fastapi import Request
from sqlalchemy.orm import Session

from backend.models import User
from backend.services.auth.tokens.email_tokens import (
    issue_verification_token,
    consume_verification_token,
)
from backend.services.auth.verification.core import (
    VerificationPurpose,
    RESEND_MIN_INTERVAL_MINUTES,
    VerificationEmailRateLimitedError,
    utcnow,
    get_latest_token_for_user,
)
from backend.services.email.client import send_signup_verification_email


def issue_signup_verification_token(
    db: Session,
    user: User,
    *,
    expires_in_minutes: int | None = None,
) -> str:
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
    user, _token = consume_verification_token(
        db=db,
        public_token=public_token,
        purpose=VerificationPurpose.SIGNUP,
    )

    user.is_active = True
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def send_signup_verification_for_user(
    db: Session,
    user: User,
    *,
    request: Request,
) -> str:
    public_token = issue_signup_verification_token(db=db, user=user)
    verify_url = request.url_for("verify_email", token=public_token).replace(scheme="https")

    send_signup_verification_email(
        to_email=user.email,
        verify_url=str(verify_url),
    )
    return str(verify_url)


def resend_signup_verification_for_candidate(
    db: Session,
    user: User | None,
    *,
    request: Request,
) -> None:
    min_interval_minutes = RESEND_MIN_INTERVAL_MINUTES[VerificationPurpose.SIGNUP]

    if user is None or user.is_active:
        return

    latest = get_latest_token_for_user(
        db=db,
        user_id=user.id,
        purpose=VerificationPurpose.SIGNUP,
    )
    if latest is not None:
        now = utcnow()
        if latest.created_at + timedelta(minutes=min_interval_minutes) > now:
            raise VerificationEmailRateLimitedError(
                f"驗證信寄送太頻繁，請在 {min_interval_minutes} 分鐘後再試。"
            )

    send_signup_verification_for_user(db=db, user=user, request=request)


def resend_signup_verification_for_email(
    db: Session,
    email: str,
    *,
    request: Request,
) -> None:
    user = db.query(User).filter(User.email == email).first()
    resend_signup_verification_for_candidate(db=db, user=user, request=request)
