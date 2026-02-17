# backend/core/obs_events.py
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any


def log_loki_event(
    logger: logging.Logger,
    *,
    event: str,
    source: str,
    stage: str,
    gate_name: str,
    env: str,
    **fields: Any,
) -> None:
    payload: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        # Loki labels（低基數）：source / stage / gate_name / env
        "source": source,
        "stage": stage,
        "gate_name": gate_name,
        "env": env,
    }
    # 其他高基數內容放 body fields：run_id / item_key / url / detail_json...
    payload.update(fields)

    logger.info(json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str))
