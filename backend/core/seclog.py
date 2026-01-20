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
