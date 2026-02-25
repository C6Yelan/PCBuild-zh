# backend/tests/test_account_enumeration.py
import os
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from fastapi import FastAPI, Request, Response

import backend.api.routes.auth.register as register_route
import backend.api.routes.auth.password.forgot_password as forgot_password_route
import backend.api.routes.auth.verification.resend_verification as resend_verification_route
from backend.schemas.auth import ForgotPasswordIn, RegisterIn, ResendVerificationIn
from backend.services.auth.verification.core import VerificationEmailRateLimitedError


class _FakeQuery:
    def __init__(self, db: "_FakeDB") -> None:
        self._db = db

    def filter(self, *args, **kwargs) -> "_FakeQuery":
        return self

    def order_by(self, *args, **kwargs) -> "_FakeQuery":
        return self

    def first(self):
        if self._db.query_results:
            return self._db.query_results.pop(0)
        return None


class _FakeDB:
    def __init__(self, query_results: list[object | None]) -> None:
        self.query_results = list(query_results)
        self.added: list[object] = []
        self.commits = 0
        self.refreshed: list[object] = []

    def query(self, _model) -> _FakeQuery:
        return _FakeQuery(self)

    def add(self, obj: object) -> None:
        self.added.append(obj)

    def commit(self) -> None:
        self.commits += 1

    def refresh(self, obj: object) -> None:
        self.refreshed.append(obj)


def _make_request(path: str) -> Request:
    app = FastAPI()
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
        "root_path": "",
        "app": app,
    }
    return Request(scope)


def test_register_response_consistent_between_existing_and_non_existing(monkeypatch) -> None:
    monkeypatch.setattr(register_route, "send_signup_verification_for_user", lambda **_kwargs: None)
    monkeypatch.setattr(register_route, "hash_password", lambda _plain: "hashed")
    fn = register_route.register.__wrapped__
    body = RegisterIn(email="u@example.com", username="user1", password="12345678")

    req_missing = _make_request("/api/auth/register")
    req_existing = _make_request("/api/auth/register")

    resp_missing = fn(
        body=body,
        request=req_missing,
        response=Response(),
        db=_FakeDB([None, None]),
    )
    resp_existing = fn(
        body=body,
        request=req_existing,
        response=Response(),
        db=_FakeDB([SimpleNamespace(id=1, email=body.email, is_active=False), None]),
    )

    assert resp_missing == resp_existing
    assert resp_missing["ok"] is True


def test_forgot_password_response_consistent_between_existing_and_non_existing(monkeypatch) -> None:
    monkeypatch.setattr(forgot_password_route, "send_password_reset_for_user", lambda **_kwargs: None)
    fn = forgot_password_route.forgot_password.__wrapped__
    body = ForgotPasswordIn(email="u@example.com")

    resp_missing = fn(
        body=body,
        request=_make_request("/api/auth/forgot-password"),
        response=Response(),
        db=_FakeDB([None]),
    )
    resp_existing = fn(
        body=body,
        request=_make_request("/api/auth/forgot-password"),
        response=Response(),
        db=_FakeDB([SimpleNamespace(id=1, email=body.email, is_active=True)]),
    )

    assert resp_missing == resp_existing
    assert resp_missing["ok"] is True


def test_resend_verification_response_consistent_between_existing_and_non_existing(monkeypatch) -> None:
    monkeypatch.setattr(resend_verification_route, "resend_signup_verification_for_email", lambda **_kwargs: None)
    fn = resend_verification_route.resend_verification.__wrapped__
    body = ResendVerificationIn(email="u@example.com")

    resp_missing = fn(
        body=body,
        request=_make_request("/api/auth/resend-verification"),
        response=Response(),
        db=_FakeDB([None]),
    )
    resp_existing = fn(
        body=body,
        request=_make_request("/api/auth/resend-verification"),
        response=Response(),
        db=_FakeDB([SimpleNamespace(id=1, email=body.email, is_active=False)]),
    )

    assert resp_missing == resp_existing
    assert resp_missing["ok"] is True


def test_forgot_password_rate_limit_signal_consistent_between_states(monkeypatch) -> None:
    def _raise_rate_limited(**_kwargs):
        raise VerificationEmailRateLimitedError("rate limited")

    monkeypatch.setattr(forgot_password_route, "send_password_reset_for_user", _raise_rate_limited)
    fn = forgot_password_route.forgot_password.__wrapped__
    body = ForgotPasswordIn(email="u@example.com")

    resp_missing = fn(
        body=body,
        request=_make_request("/api/auth/forgot-password"),
        response=Response(),
        db=_FakeDB([None]),
    )
    resp_existing_rate_limited = fn(
        body=body,
        request=_make_request("/api/auth/forgot-password"),
        response=Response(),
        db=_FakeDB([SimpleNamespace(id=1, email=body.email, is_active=True)]),
    )

    assert resp_missing == resp_existing_rate_limited
    assert resp_missing["ok"] is True


def test_resend_verification_rate_limit_signal_consistent_between_states(monkeypatch) -> None:
    def _raise_rate_limited(**_kwargs):
        raise VerificationEmailRateLimitedError("rate limited")

    monkeypatch.setattr(resend_verification_route, "resend_signup_verification_for_email", _raise_rate_limited)
    fn = resend_verification_route.resend_verification.__wrapped__
    body = ResendVerificationIn(email="u@example.com")

    resp_missing = fn(
        body=body,
        request=_make_request("/api/auth/resend-verification"),
        response=Response(),
        db=_FakeDB([None]),
    )
    resp_existing_rate_limited = fn(
        body=body,
        request=_make_request("/api/auth/resend-verification"),
        response=Response(),
        db=_FakeDB([SimpleNamespace(id=1, email=body.email, is_active=False)]),
    )

    assert resp_missing == resp_existing_rate_limited
    assert resp_missing["ok"] is True
