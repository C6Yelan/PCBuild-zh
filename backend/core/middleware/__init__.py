# backend/core/middleware/__init__.py
from __future__ import annotations

from fastapi import FastAPI
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from backend.core.middleware.access.cors import add_cors_middleware
from backend.core.middleware.security.csrf import add_csrf_protection_middleware
from backend.core.middleware.security.security_headers import add_security_headers_middleware
from backend.core.middleware.gates.debug_gate import add_debug_gate_middleware
from backend.core.middleware.throttling.rate_limit import limiter
from backend.core.middleware.throttling.rate_limit_handler import rate_limit_exceeded_handler


def add_app_middlewares(app: FastAPI, settings) -> None:
    """
    集中掛載所有 middleware，維持既有行為與順序。

    FastAPI middleware stack：最後加入的 middleware 會是最外層（request 先跑它）。
    因此本函數不掛 TrustedHostMiddleware，讓 app_factory 保持最後加入。
    """
    if settings.rate_limit_enabled:
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
        app.add_middleware(SlowAPIMiddleware)

    # 維持你原本 app_factory 的順序：CORS -> CSRF -> security headers -> debug gate
    add_cors_middleware(app)
    add_csrf_protection_middleware(app)
    add_security_headers_middleware(app)
    add_debug_gate_middleware(app)
