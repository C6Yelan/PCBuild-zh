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

def _fmt_value(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)

    s = str(v)
    if any(ch in s for ch in (' ', '"', '=')):
        s = s.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{s}"'
    return s


def log_operation(event: str, **fields: Any) -> None:
    # 避免敏感資訊進入 log（最小防呆；真正敏感資料仍不應傳進來）
    safe_fields = {k: v for k, v in fields.items() if k.lower() not in _SENSITIVE_KEYS}

    if "method" not in safe_fields:
        safe_fields["method"] = "-"
    if "path" not in safe_fields:
        safe_fields["path"] = "-"

    # 統一 key=value 格式，方便 Loki/Grafana 用字串過濾
    kv = " ".join(f"{k}={_fmt_value(safe_fields[k])}" for k in sorted(safe_fields.keys()))
    msg = f"category=operation event={event}" + (f" {kv}" if kv else "")
    _logger.info(msg)
