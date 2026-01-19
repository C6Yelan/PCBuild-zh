# backend/core/oplog.py
from __future__ import annotations

import logging
from typing import Any

_logger = logging.getLogger("pcbuild.operation")

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


def log_operation(event: str, **fields: Any) -> None:
    # 避免敏感資訊進入 log（最小防呆；真正敏感資料仍不應傳進來）
    safe_fields = {k: v for k, v in fields.items() if k.lower() not in _SENSITIVE_KEYS}

    # 統一 key=value 格式，方便 Loki/Grafana 用字串過濾
    kv = " ".join(f"{k}={safe_fields[k]}" for k in sorted(safe_fields.keys()))
    msg = f"category=operation event={event}" + (f" {kv}" if kv else "")
    _logger.info(msg)
