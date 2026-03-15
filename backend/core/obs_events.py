# backend/core/obs_events.py
from __future__ import annotations

import logging
import os
from typing import Any

from backend.core.log_event_lines import build_log_event_message


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
    msg = build_log_event_message(
        prefix_pairs=[
            ("category", category),
            ("event", event),
            ("source", source),
            ("stage", stage),
            ("gate_name", gate_name),
            ("env", env),
        ],
        fields=fields,
        structured_json=True,
        quote_mode="whitespace",
        skip_none=True,
    )
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


def ensure_cli_logging(*, logger: logging.Logger, log_level: str | None = None) -> None:
    """
    CLI 工具情境下，沿用 app 端同一套 logging 格式與 handler。
    讓工具事件與 auth/session 在 Grafana/Loki 的欄位一致（level/logger 等）。
    """
    from backend.core.logging import configure_logging

    level_name = (log_level or os.getenv("LOG_LEVEL") or "INFO").upper()
    configure_logging(log_level=level_name)
    level = getattr(logging, level_name, logging.INFO)
    logging.getLogger().setLevel(level)
    logger.setLevel(level)
