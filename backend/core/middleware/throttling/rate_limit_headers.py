from __future__ import annotations

from fastapi import FastAPI, Request

# 路徑由既有 router 定義確認：
# /api/auth (backend/api/routes/auth/__init__.py) +
# /register, /forgot-password, /resend-verification
_GENERIC_OK_PATHS = {
    "/api/auth/register",
    "/api/auth/forgot-password",
    "/api/auth/resend-verification",
}

_RATE_LIMIT_HEADERS = (
    "Retry-After",
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
    "X-RateLimit-Reset",
)


def add_generic_ok_rate_limit_header_cleanup_middleware(app: FastAPI) -> None:
    @app.middleware("http")
    async def _cleanup_rate_limit_headers_for_generic_ok(request: Request, call_next):
        response = await call_next(request)

        if request.url.path in _GENERIC_OK_PATHS and response.status_code == 200:
            for key in _RATE_LIMIT_HEADERS:
                try:
                    del response.headers[key]
                except KeyError:
                    pass

        return response

