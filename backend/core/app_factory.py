# backend/core/app_factory.py
from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from backend.core.middleware import add_app_middlewares
from backend.core.bootstrap.routes import include_api_routes
from backend.core.settings import get_settings
from backend.core.bootstrap.static_site import mount_static_site
from backend.core.logging import configure_logging, request_log_middleware
from backend.core.middleware.throttling.rate_limit_headers import (
    add_generic_ok_rate_limit_header_cleanup_middleware,
)
from backend.core.oplog import log_operation


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(log_level=settings.log_level)

    openapi_url = None
    docs_url = None
    redoc_url = None
    if settings.debug_routes_enabled:
        openapi_url = "/openapi.json"
        docs_url = "/docs"
        redoc_url = "/redoc"

    app = FastAPI(
        openapi_url=openapi_url,
        docs_url=docs_url,
        redoc_url=redoc_url,
    )
    app.state.request_log_mode = settings.request_log_mode

    add_app_middlewares(app, settings)

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=[
            "pcbuild.redfiretw.xyz",
            "localhost",
            "127.0.0.1",
        ],
    )
    @app.on_event("startup") # 未來會變更成更新的啟動程序方式
    async def _oplog_startup() -> None:
        log_operation("app_start", component="fastapi")

    include_api_routes(app)
    mount_static_site(app)
    app.middleware("http")(request_log_middleware)
    # 最後註冊：在 response 返回前最後清理 generic 200 的 rate-limit headers
    add_generic_ok_rate_limit_header_cleanup_middleware(app)
    return app
