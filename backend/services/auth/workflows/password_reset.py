# backend/services/auth/workflows/password_reset.py
from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from backend.models import User
from backend.services.auth.tokens.email_tokens import issue_password_reset_token_for_user
from backend.services.email.client import send_password_reset_email


def send_password_reset_for_user(
    db: Session,
    user: User,
    *,
    request: Request,
) -> str:
    public_token = issue_password_reset_token_for_user(db=db, user=user)
    reset_url = request.url_for("reset_password", token=public_token).replace(scheme="https")

    send_password_reset_email(
        to_email=user.email,
        reset_url=str(reset_url),
    )
    return str(reset_url)