# backend/tests/test_login_csrf.py
import asyncio
import os

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from fastapi import FastAPI
from fastapi import Request
from fastapi.responses import JSONResponse

from backend.core.settings import get_settings
from backend.core.middleware.security.csrf import add_csrf_protection_middleware


def _build_app() -> FastAPI:
    app = FastAPI()
    add_csrf_protection_middleware(app)
    return app


def _build_request(path: str, *, origin: str | None = None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if origin is not None:
        headers.append((b"origin", origin.encode("utf-8")))

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
        "root_path": "",
    }
    return Request(scope)


async def _call_next_ok(_request: Request) -> JSONResponse:
    return JSONResponse(status_code=200, content={"ok": True})


def _run_csrf_guard(path: str, *, origin: str | None) -> JSONResponse:
    app = _build_app()
    dispatch = app.user_middleware[0].kwargs["dispatch"]
    request = _build_request(path, origin=origin)
    response = asyncio.run(dispatch(request, _call_next_ok))
    return response


def test_login_without_session_cookie_rejects_untrusted_origin(monkeypatch) -> None:
    monkeypatch.setenv("CSRF_TRUSTED_ORIGINS", "https://pcbuild.redfiretw.xyz")
    get_settings.cache_clear()

    resp = _run_csrf_guard("/api/auth/login", origin="https://evil.example")

    assert resp.status_code == 403
    assert resp.body == b'{"errors":{"_global":"CSRF protection: invalid origin"}}'


def test_login_without_session_cookie_allows_trusted_origin(monkeypatch) -> None:
    monkeypatch.setenv("CSRF_TRUSTED_ORIGINS", "https://pcbuild.redfiretw.xyz")
    get_settings.cache_clear()

    resp = _run_csrf_guard("/api/auth/login", origin="https://pcbuild.redfiretw.xyz")

    assert resp.status_code != 403


def test_non_login_post_without_session_cookie_keeps_existing_behavior(monkeypatch) -> None:
    monkeypatch.setenv("CSRF_TRUSTED_ORIGINS", "https://pcbuild.redfiretw.xyz")
    get_settings.cache_clear()

    resp = _run_csrf_guard("/api/auth/other", origin="https://evil.example")

    assert resp.status_code == 200

