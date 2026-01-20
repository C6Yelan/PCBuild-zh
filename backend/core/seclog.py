# backend/core/seclog.py
from __future__ import annotations

import logging
from typing import Any

_logger = logging.getLogger("pcbuild.security")

_SENSITIVE_KEYS = {
    "password",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "cookie",
    "set_cookie",
    "session",
}


def log_security(event: str, **fields: Any) -> None:
    # 最小防呆：避免敏感資訊進入 log
    safe_fields = {k: v for k, v in fields.items() if k.lower() not in _SENSITIVE_KEYS}

    # 統一 key=value（logfmt 風格），便於 Alloy stage.logfmt 解析
    kv = " ".join(f"{k}={safe_fields[k]}" for k in sorted(safe_fields.keys()))
    msg = f"category=security event={event}" + (f" {kv}" if kv else "")
    _logger.warning(msg)

def client_ip(request: Any) -> str:
    headers = getattr(request, "headers", {}) or {}
    cf_ip = headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip

    xff = headers.get("x-forwarded-for") or ""
    if xff:
        return xff.split(",", 1)[0].strip() or "-"

    client = getattr(request, "client", None)
    host = getattr(client, "host", None) if client else None
    return host or "-"


def security_ctx(request: Any, *, include_path: bool = True) -> dict[str, str]:
    ctx = {
        "client": client_ip(request),
        "method": getattr(request, "method", "-"),
    }
    if include_path:
        url = getattr(request, "url", None)
        path = getattr(url, "path", None) if url else None
        ctx["path"] = path or "-"
    return ctx
