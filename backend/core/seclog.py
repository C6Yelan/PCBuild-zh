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

# 事件分級：成功/正常流程用 INFO；可疑/阻擋用 WARNING；真正異常才用 ERROR
_EVENT_LEVELS: dict[str, int] = {
    # ---- expected / success ----
    "password_reset_email_sent": logging.INFO,
    "password_reset_token_valid": logging.INFO,
    "email_verify_success": logging.INFO,
    "session_rotated": logging.INFO,
    "session_revoked": logging.INFO,

    # ---- suspicious / blocked ----
    "rate_limited": logging.WARNING,
    "csrf_invalid_origin": logging.WARNING,
    "authz_denied": logging.WARNING,
    "password_reset_token_invalid": logging.WARNING,
    "email_verify_token_invalid": logging.WARNING,
    "session_invalid_cookie": logging.WARNING,

    # 常見噪音來源：未帶 session cookie（多半是機器掃描/健康檢查/誤打）
    # 先放 INFO，之後再做降噪（limit/drop）比較合理
    "authn_missing_session_cookie": logging.INFO,
}


def _fmt_value(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    # logfmt：含空白、等號、雙引號時需要加引號並跳脫
    if any(ch in s for ch in (' ', '"', '=')):
        s = s.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{s}"'
    return s


def log_security(event: str, **fields: Any) -> None:
    # 最小防呆：避免敏感資訊進入 log
    safe_fields = {k: v for k, v in fields.items() if k.lower() not in _SENSITIVE_KEYS}

    # 統一 key=value（logfmt 風格），便於 pipeline 解析
    kv = " ".join(f"{k}={_fmt_value(safe_fields[k])}" for k in sorted(safe_fields.keys()))
    msg = f"category=security event={event}" + (f" {kv}" if kv else "")

    level = _EVENT_LEVELS.get(event, logging.WARNING)
    _logger.log(level, msg)
