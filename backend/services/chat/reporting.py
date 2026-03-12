# backend/services/chat/reporting.py
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


REPORT_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_report_filename_component(value: str, fallback: str) -> str:
    normalized = REPORT_FILENAME_SAFE_RE.sub("_", value).strip("._")
    return normalized or fallback


def build_timestamped_report_path(
    *,
    root_dir: Path,
    report_dir_name: str,
    provider: str,
    model: str,
    ran_at: datetime,
) -> Path:
    timestamp = ran_at.strftime("%Y%m%dT%H%M%SZ")
    safe_provider = sanitize_report_filename_component(provider, "unknown-provider")
    safe_model = sanitize_report_filename_component(model, "unknown-model")
    return root_dir / report_dir_name / f"{timestamp}__{safe_provider}__{safe_model}.json"


def write_report_payload(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
