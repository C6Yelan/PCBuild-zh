# backend/core/app_factory.py
from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from backend.core.middleware import add_app_middlewares
from backend.core.bootstrap.routes import include_api_routes
from backend.core.settings import get_settings
from backend.core.bootstrap.static_site import mount_static_site
from backend.core.logging import configure_logging, request_log_middleware


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(log_level=settings.log_level)

    app = FastAPI()
    app.state.request_log_mode = settings.request_log_mode
    app.middleware("http")(request_log_middleware)

    add_app_middlewares(app, settings)

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=[
            "pcbuild.redfiretw.xyz",
            "localhost",
            "127.0.0.1",
        ],
    )

    include_api_routes(app)
    mount_static_site(app)
    return app

