# backend/core/cmiddleware/security/csrf.py
from __future__ import annotations

from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from backend.core.settings import get_settings
from backend.core.seclog import log_security
from backend.api.auth.config import SESSION_COOKIE_NAME


_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_API_PREFIX = "/api"
_ALWAYS_CHECK_PATHS = {
    "/api/auth/login",
}


def _normalize_origin(origin: str) -> str:
    o = origin.strip().rstrip("/")
    return o


def _origin_from_referer(referer: str) -> str | None:
    try:
        u = urlparse(referer)
        if not u.scheme or not u.netloc:
            return None
        return f"{u.scheme}://{u.netloc}"
    except Exception:
        return None


def add_csrf_protection_middleware(app: FastAPI) -> None:
    """
    針對 cookie-based session 的 state-changing API：
    - 若請求帶 cookie，且為 unsafe method，則要求 Origin/Referer 必須屬於信任清單。
    OWASP 建議對狀態變更請求採取 CSRF 防護；SameSite 僅作為額外防護層。:contentReference[oaicite:1]{index=1}
    """
    settings = get_settings()
    trusted_raw = getattr(settings, "csrf_trusted_origins", "") or ""
    trusted = {
        _normalize_origin(x)
        for x in trusted_raw.split(",")
        if x.strip()
    }

    @app.middleware("http")
    async def _csrf_guard(request: Request, call_next):
        # 只管 API，且只管會改狀態的方法
        if not request.url.path.startswith(_API_PREFIX) or request.method not in _UNSAFE_METHODS:
            return await call_next(request)

        # 一般情況：僅對 cookie-based session 的 unsafe request 做檢查。
        # 但 login 端點會建立 session cookie，因此即使尚未有 cookie 也要做來源檢查。
        has_session_cookie = SESSION_COOKIE_NAME in request.cookies
        if (not has_session_cookie) and (request.url.path not in _ALWAYS_CHECK_PATHS):
            return await call_next(request)

        origin = request.headers.get("origin")
        if origin:
            req_origin = _normalize_origin(origin)
        else:
            referer = request.headers.get("referer", "")
            ro = _origin_from_referer(referer) if referer else None
            req_origin = _normalize_origin(ro) if ro else None

        # 未設定信任清單或來源不在清單：拒絕（fail-closed）
        if not trusted or not req_origin or req_origin not in trusted:
            log_security(
                "csrf_block",
                method=request.method,
                path=request.url.path,
                client=getattr(request.client, "host", "-"),
                origin=req_origin or "-",
            )
            return JSONResponse(
                status_code=403,
                content={"errors": {"_global": "CSRF protection: invalid origin"}},
            )

        return await call_next(request)
