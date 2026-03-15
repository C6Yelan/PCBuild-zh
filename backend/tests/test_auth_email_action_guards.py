from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request

os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/pcbuild_auth_test.db")

from backend.api.auth.config import RESEND_SIGNUP_MIN_INTERVAL_SECONDS
from backend.api.routes.auth._shared import email_action_guards
from backend.api.routes.auth.password.forgot_password import forgot_password
from backend.api.routes.auth.verification.resend_verification import resend_verification
from backend.schemas.auth import ForgotPasswordIn, ResendVerificationIn
from backend.services.auth.verification.core import (
    VerificationEmailRateLimitedError,
    VerificationPurpose,
)


def _request(path: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": [(b"x-forwarded-for", b"203.0.113.5")],
            "client": ("203.0.113.5", 443),
            "scheme": "https",
            "server": ("testserver", 443),
        }
    )


def test_raise_email_action_cooldown_keeps_retry_after_and_log_fields(monkeypatch) -> None:
    logged: list[tuple[str, dict[str, object]]] = []
    now = datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc)
    latest = SimpleNamespace(created_at=now - timedelta(seconds=53))
    user = SimpleNamespace(id=42)

    monkeypatch.setattr(email_action_guards, "utcnow", lambda: now)
    monkeypatch.setattr(email_action_guards, "get_latest_token_for_user", lambda **kwargs: latest)
    monkeypatch.setattr(
        email_action_guards,
        "log_security",
        lambda event, **fields: logged.append((event, fields)),
    )

    with pytest.raises(HTTPException) as exc_info:
        email_action_guards.raise_email_action_cooldown(
            _request("/api/auth/resend-verification"),
            db=object(),
            user=user,
            purpose=VerificationPurpose.SIGNUP,
            cooldown_seconds=60,
            event="email_verification_resend_rate_limited",
            message="驗證信寄送太頻繁，請稍後再試。",
            email="user@example.com",
            user_id=user.id,
        )

    exc = exc_info.value
    assert exc.status_code == 429
    assert exc.headers["Retry-After"] == "7"
    assert exc.detail == {"errors": {"_global": "驗證信寄送太頻繁，請稍後再試。"}}
    assert logged == [
        (
            "email_verification_resend_rate_limited",
            {
                "client": "203.0.113.5",
                "method": "POST",
                "path": "/api/auth/resend-verification",
                "email_domain": "example.com",
                "user_id": 42,
                "retry_after": 7,
            },
        )
    ]


def test_resend_verification_success_keeps_retry_after_header(monkeypatch) -> None:
    response = Response()

    monkeypatch.setattr(
        "backend.api.routes.auth.verification.resend_verification.try_get_current_user",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "backend.api.routes.auth.verification.resend_verification.log_email_action_security_event",
        lambda *args, **kwargs: None,
    )

    result = resend_verification.__wrapped__(
        ResendVerificationIn(email=None),
        _request("/api/auth/resend-verification"),
        response,
        object(),
    )

    assert result == {"ok": True}
    assert response.headers["Retry-After"] == str(RESEND_SIGNUP_MIN_INTERVAL_SECONDS)


def test_forgot_password_rate_limited_keeps_429_contract(monkeypatch) -> None:
    request = _request("/api/auth/forgot-password")
    response = Response()
    user = SimpleNamespace(id=99)

    monkeypatch.setattr(
        "backend.api.routes.auth.password.forgot_password.validate_email_action_email",
        lambda *args, **kwargs: "user@example.com",
    )
    monkeypatch.setattr(
        "backend.api.routes.auth.password.forgot_password.find_user_by_email",
        lambda *args, **kwargs: user,
    )
    monkeypatch.setattr(
        "backend.api.routes.auth.password.forgot_password.send_password_reset_for_user",
        lambda **kwargs: (_ for _ in ()).throw(
            VerificationEmailRateLimitedError("too many requests")
        ),
    )

    def _raise_cooldown(*args, **kwargs):
        raise email_action_guards.build_rate_limited_exception(
            message=kwargs["message"],
            retry_after=11,
        )

    monkeypatch.setattr(
        "backend.api.routes.auth.password.forgot_password.raise_email_action_cooldown",
        _raise_cooldown,
    )

    with pytest.raises(HTTPException) as exc_info:
        forgot_password(
            ForgotPasswordIn(email="user@example.com"),
            request,
            response,
            object(),
        )

    exc = exc_info.value
    assert exc.status_code == 429
    assert exc.headers["Retry-After"] == "11"
    assert exc.detail == {"errors": {"_global": "重設密碼請求太頻繁，請稍後再試。"}}
