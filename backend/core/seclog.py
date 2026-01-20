# backend/core/seclog.py
from __future__ import annotations

import logging
from typing import Any

_logger = logging.getLogger("pcbuild.security")

# 避免敏感資訊進 log（key 比對採 lower）
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

# 事件分級：成功/預期流程 INFO；阻擋/可疑 WARNING；真正異常 ERROR
# 未列出的事件預設 WARNING（保守）
_EVENT_LEVELS: dict[str, int] = {
    # --- auth / access control ---
    "authn_success": logging.INFO,
    "authn_failed": logging.WARNING,
    "authn_input_invalid": logging.WARNING,
    "authn_missing_session_cookie": logging.INFO,   # 先 INFO，後續再做降噪
    "authz_denied": logging.WARNING,

    # --- rate limiting / abuse ---
    "rate_limited": logging.WARNING,

    # --- session ---
    "session_created": logging.INFO,
    "session_rotated": logging.INFO,
    "session_revoked": logging.INFO,
    "session_invalid_cookie": logging.WARNING,

    # --- email verify ---
    "email_verify_success": logging.INFO,
    "email_verify_token_invalid": logging.WARNING,

    # --- password reset ---
    "password_reset_email_sent": logging.INFO,
    "password_reset_request_unknown": logging.INFO,
    "password_reset_rate_limited": logging.WARNING,
    "password_reset_token_valid": logging.INFO,
    "password_reset_token_invalid": logging.WARNING,
    "password_reset_policy_violation": logging.WARNING,
    "password_reset_success": logging.INFO,

    # --- verification token ---
    "verification_token_issued": logging.INFO,
    "verification_token_consumed": logging.INFO,
    "verification_token_rejected": logging.WARNING,
}

def _fmt_value(v: Any) -> str:
    """
    盡量符合 logfmt 可解析的 value：
    - key=value 以空白分隔（含空白/等號/引號的 value 用雙引號包起來）
    - 內部 " 與 反斜線 做基本跳脫
    """
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


def log_security(event: str, **fields: Any) -> None:
    # 最小防呆：避免敏感資訊進入 log
    safe_fields = {k: v for k, v in fields.items() if k.lower() not in _SENSITIVE_KEYS}

    # 統一 key=value（logfmt 風格），便於 Alloy stage.logfmt 解析
    kv = " ".join(f"{k}={_fmt_value(safe_fields[k])}" for k in sorted(safe_fields.keys()))
    msg = f"category=security event={event}" + (f" {kv}" if kv else "")

    level = _EVENT_LEVELS.get(event, logging.WARNING)
    _logger.log(level, msg)


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
