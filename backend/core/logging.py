# backend/core/logging.py
from __future__ import annotations

import logging
import logging.config
import time
import uuid
from typing import Callable, Awaitable

from fastapi import Request, Response

_configured = False


def configure_logging(*, log_level: str) -> None:
    """
    Configure application + uvicorn loggers.

    Strategy:
    - Emit logs to stdout (container-friendly, 12-factor).
    - Keep existing loggers enabled (uvicorn, etc.).
    """
    global _configured
    if _configured:
        return

    level = (log_level or "INFO").upper()

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
                },
            },
            "handlers": {
                "stdout": {
                    "class": "logging.StreamHandler",
                    "formatter": "default",
                    "stream": "ext://sys.stdout",
                }
            },
            "root": {
                "level": level,
                "handlers": ["stdout"],
            },
            # Make sure uvicorn loggers follow the same handler/level
            "loggers": {
                "uvicorn": {"level": level, "handlers": ["stdout"], "propagate": False},
                "uvicorn.error": {"level": level, "handlers": ["stdout"], "propagate": False},
                "uvicorn.access": {"level": "WARNING", "handlers": ["stdout"], "propagate": False},
                "pcbuild.operation": {"level": "INFO", "handlers": ["stdout"], "propagate": False},
                "pcbuild.request": {"level": level, "handlers": ["stdout"], "propagate": False},
            },
        }
    )

    _configured = True


async def request_log_middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    """
    Minimal request logging without leaking sensitive query params (e.g., token in URL).

    Logs:
    - errors (exceptions) with stack trace
    - slow requests (>= 800ms) at WARNING
    - 4xx/5xx at WARNING
    """
    mode = getattr(request.app.state, "request_log_mode", "errors")
    logger = logging.getLogger("pcbuild.request")

    req_id = uuid.uuid4().hex[:12]
    start = time.perf_counter()

    try:
        response = await call_next(request)
    except Exception:
        dur_ms = (time.perf_counter() - start) * 1000
        # Do NOT log request.url (may include query tokens). Use path only.
        logger.exception(
             "category=error event=request_failed method=%s path=%s duration_ms=%.1f request_id=%s client=%s",
            request.method,
            request.url.path,
            dur_ms,
            req_id,
            getattr(request.client, "host", "-"),
        )
        raise

    dur_ms = (time.perf_counter() - start) * 1000
    status = response.status_code

    if status >= 400:
        logger.warning(
             "category=error event=request_error method=%s path=%s status=%s duration_ms=%.1f request_id=%s client=%s",
            request.method,
            request.url.path,
            status,
            dur_ms,
            req_id,
            getattr(request.client, "host", "-"),
        )
    elif dur_ms >= 800:
        logger.warning(
            "category=access event=request_slow method=%s path=%s status=%s duration_ms=%.1f request_id=%s",
            request.method,
            request.url.path,
            status,
            dur_ms,
            req_id,
        )
    elif mode == "all":
        logger.info(
            "category=access event=request_ok method=%s path=%s status=%s duration_ms=%.1f request_id=%s",
            request.method,
            request.url.path,
            status,
            dur_ms,
            req_id,
        )

    return response
