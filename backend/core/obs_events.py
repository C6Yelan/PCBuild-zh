# backend/core/obs_events.py
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

_NEED_QUOTE = re.compile(r'[=\s"]')


def _q(s: str) -> str:
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


def _lf(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, (dict, list)):
        s = json.dumps(v, ensure_ascii=False, separators=(",", ":"))
        return _q(s)
    s = str(v)
    return _q(s) if _NEED_QUOTE.search(s) else s


def log_loki_event(
    logger: logging.Logger,
    *,
    level: int = logging.INFO,
    category: str = "pipeline",
    event: str,
    source: str,
    stage: str,
    gate_name: str | None = None,
    env: str | None = None,
    **fields: Any,
) -> None:
    # 固定欄位先放，順序穩定方便 grep / 比對
    parts: list[tuple[str, Any]] = [
        ("category", category),
        ("event", event),
        ("source", source),
        ("stage", stage),
    ]
    if gate_name is not None:
        parts.append(("gate_name", gate_name))
    if env is not None:
        parts.append(("env", env))

    # 其他欄位：None 就略過，避免噪音
    for k in sorted(fields.keys()):
        v = fields[k]
        if v is None:
            continue
        parts.append((k, v))

    msg = " ".join(f"{k}={_lf(v)}" for k, v in parts)
    logger.log(level, msg)
    # 在 docker compose exec 跑工具時，stdout 不一定會進 PID1 的 docker logs。
    # 若設了環境變數，額外把同一行寫到 /proc/1/fd/1，確保 Loki 收得到。
    if os.getenv("PCBUILD_LOG_TO_PID1", "").lower() in ("1", "true", "yes", "on"):
        pid1_line = f"level={logging.getLevelName(level)} logger={logger.name} {msg}"
        try:
            with open("/proc/1/fd/1", "a", encoding="utf-8") as f:
                f.write(pid1_line + "\n")
        except Exception:
            # 不要讓觀測機制影響主流程
            pass
