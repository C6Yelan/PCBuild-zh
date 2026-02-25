import asyncio
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi import Response
from fastapi import Request

import backend.core.logging as logging_mod


class _FakeLogger:
    def __init__(self) -> None:
        self.info_calls: list[tuple[str, tuple[object, ...]]] = []
        self.warning_calls: list[tuple[str, tuple[object, ...]]] = []
        self.exception_calls: list[tuple[str, tuple[object, ...]]] = []

    def info(self, msg: str, *args: object) -> None:
        self.info_calls.append((msg, args))

    def warning(self, msg: str, *args: object) -> None:
        self.warning_calls.append((msg, args))

    def exception(self, msg: str, *args: object) -> None:
        self.exception_calls.append((msg, args))


def _make_request(path: str, *, mode: str = "all") -> Request:
    app = FastAPI()
    app.state.request_log_mode = mode
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
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


def _logged_path_for_ok_request(monkeypatch, path: str) -> str:
    request = _make_request(path, mode="all")
    fake_logger = _FakeLogger()
    original_get_logger = logging_mod.logging.getLogger

    def _patched_get_logger(name=None):
        if name == "pcbuild.request":
            return fake_logger
        if name is None:
            return original_get_logger()
        return original_get_logger(name)

    monkeypatch.setattr(logging_mod.logging, "getLogger", _patched_get_logger)
    monkeypatch.setattr(logging_mod.uuid, "uuid4", lambda: SimpleNamespace(hex="f" * 32))

    async def _call_next(_request: Request) -> Response:
        return Response(status_code=200)

    asyncio.run(logging_mod.request_log_middleware(request, _call_next))
    assert fake_logger.info_calls
    return str(fake_logger.info_calls[-1][1][1])


def test_redacts_verify_email_token_in_request_log(monkeypatch) -> None:
    assert _logged_path_for_ok_request(monkeypatch, "/verify-email/abc") == "/verify-email/[REDACTED]"


def test_redacts_reset_password_token_in_request_log(monkeypatch) -> None:
    assert _logged_path_for_ok_request(monkeypatch, "/reset-password/xyz") == "/reset-password/[REDACTED]"


def test_redacts_prefixed_verify_email_token_in_request_log(monkeypatch) -> None:
    assert (
        _logged_path_for_ok_request(monkeypatch, "/api/auth/verify-email/abc")
        == "/api/auth/verify-email/[REDACTED]"
    )


def test_keeps_general_path_unchanged_in_request_log(monkeypatch) -> None:
    assert _logged_path_for_ok_request(monkeypatch, "/healthz") == "/healthz"


def test_missing_token_segment_does_not_crash(monkeypatch) -> None:
    assert _logged_path_for_ok_request(monkeypatch, "/verify-email/") == "/verify-email/"
