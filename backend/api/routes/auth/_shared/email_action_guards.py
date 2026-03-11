# backend/api/routes/auth/_shared/email_action_guards.py
"""Shared cooldown, 429, and security-log helpers for auth email-action routes."""

from __future__ import annotations

import math
from datetime import timedelta
from typing import Any

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.models import User
from backend.core.seclog import security_ctx
from backend.services.auth.verification.core import (
    VerificationPurpose,
    get_latest_token_for_user,
    utcnow,
)


def _email_domain(email: str | None) -> str:
    if email and "@" in email:
        return email.split("@", 1)[-1].lower()
    return "-"


def build_email_action_log_fields(
    request: Request,
    *,
    email: str | None = None,
    user_id: Any | None = None,
    endpoint: str | None = None,
    retry_after: int | None = None,
) -> dict[str, Any]:
    fields: dict[str, Any] = dict(security_ctx(request))
    if email is not None:
        fields["email_domain"] = _email_domain(email)
    if user_id is not None:
        fields["user_id"] = user_id
    if endpoint is not None:
        fields["endpoint"] = endpoint
    if retry_after is not None:
        fields["retry_after"] = int(retry_after)
    return fields


def compute_retry_after_seconds(
    db: Session,
    *,
    user: User | None,
    purpose: VerificationPurpose,
    cooldown_seconds: int,
) -> int:
    retry_after = int(cooldown_seconds)
    if user is None:
        return retry_after

    latest = get_latest_token_for_user(
        db=db,
        user_id=user.id,
        purpose=purpose,
    )
    if latest is None:
        return retry_after

    wait_until = latest.created_at + timedelta(seconds=cooldown_seconds)
    remaining = (wait_until - utcnow()).total_seconds()
    return max(1, int(math.ceil(remaining)))


def build_rate_limited_exception(*, message: str, retry_after: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail={"errors": {"_global": message}},
        headers={"Retry-After": str(int(retry_after))},
    )
