# backend/core/oplog.py
from __future__ import annotations

import logging
from typing import Any

from backend.core.log_redaction import redact_log_mapping
from backend.core.logfmt import render_logfmt_fields

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
    safe_fields = redact_log_mapping(fields, sensitive_keys=_SENSITIVE_KEYS, mode="drop")

    if "method" not in safe_fields:
        safe_fields["method"] = "-"
    if "path" not in safe_fields:
        safe_fields["path"] = "-"

    # 統一 key=value 格式，方便 Loki/Grafana 用字串過濾
    kv = render_logfmt_fields(safe_fields)
    msg = f"category=operation event={event}" + (f" {kv}" if kv else "")
    _logger.info(msg)
