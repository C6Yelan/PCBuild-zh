# backend/services/chat/health.py
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from math import ceil
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from backend.core.oplog import log_operation
from backend.services.chat.config import get_ai_settings
from backend.services.chat.contracts import ChatRequest
from backend.services.chat.service import generate_chat_reply


_REPORT_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True, slots=True)
class ProviderHealthCase:
    case_id: str
    name: str
    request: ChatRequest


PROVIDER_HEALTH_CASES: tuple[ProviderHealthCase, ...] = (
    ProviderHealthCase(
        case_id="basic_short_qa",
        name="基本短問答",
        request=ChatRequest(user_text="請用一句話說明你能協助我什麼。"),
    ),
    ProviderHealthCase(
        case_id="format_three_points",
        name="明確格式要求",
        request=ChatRequest(user_text="請用三點列出組電腦前要先確認的事項。"),
    ),
    ProviderHealthCase(
        case_id="messages_multiturn",
        name="多輪對話 messages 模式",
        request=ChatRequest(
            messages=[
                {"role": "system", "content": "請用繁體中文簡短回答。"},
                {"role": "user", "content": "我主要拿來文書處理。"},
                {"role": "assistant", "content": "了解。"},
                {"role": "user", "content": "那 CPU 需要很高階嗎？請一句話回答。"},
            ]
        ),
    ),
    ProviderHealthCase(
        case_id="pc_build_domain_short",
        name="短領域題",
        request=ChatRequest(user_text="文書機沒有獨立顯卡可以嗎？請簡短回答。"),
    ),
    ProviderHealthCase(
        case_id="user_text_with_demand_string",
        name="user_text 模式含簡短 demand 字串",
        request=ChatRequest(
            user_text="請給我入門組機建議方向。",
            demand="預算兩萬元內，偏安靜、省電。",
        ),
    ),
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sanitize_filename_component(value: str, fallback: str) -> str:
    normalized = _REPORT_FILENAME_SAFE_RE.sub("_", value).strip("._")
    return normalized or fallback


def _percentile_nearest_rank(latencies: list[int], percentile: float) -> int:
    if not latencies:
        return 0
    ordered = sorted(latencies)
    rank = max(1, ceil((percentile / 100.0) * len(ordered)))
    return ordered[rank - 1]


def _report_path(*, root_dir: Path, provider: str, model: str, ran_at: datetime) -> Path:
    timestamp = ran_at.strftime("%Y%m%dT%H%M%SZ")
    safe_provider = _sanitize_filename_component(provider, "unknown-provider")
    safe_model = _sanitize_filename_component(model, "unknown-model")
    return (
        root_dir
        / "provider_health_reports"
        / f"{timestamp}__{safe_provider}__{safe_model}.json"
    )


def _write_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def run_provider_health_check(*, db: Session | None = None) -> dict[str, object]:
    _ = db  # smoke cases intentionally avoid DB-dependent retrieval.
    settings = get_ai_settings()
    ran_at = _utc_now()
    cases: list[dict[str, object]] = []
    latencies: list[int] = []
    error_type_counts: dict[str, int] = {}

    for case in PROVIDER_HEALTH_CASES:
        try:
            response = generate_chat_reply(case.request, db=None)
            case_ok = response.error_type is None and bool(response.text.strip())
            latency_ms = int(response.latency_ms)
            if response.error_type:
                error_type_counts[response.error_type] = (
                    error_type_counts.get(response.error_type, 0) + 1
                )
            cases.append(
                {
                    "case_id": case.case_id,
                    "name": case.name,
                    "request_id": response.request_id,
                    "ok": case_ok,
                    "latency_ms": latency_ms,
                    "error_type": response.error_type,
                    "warnings": response.warnings,
                }
            )
            latencies.append(latency_ms)
        except Exception as exc:
            error_type = type(exc).__name__
            error_type_counts[error_type] = error_type_counts.get(error_type, 0) + 1
            cases.append(
                {
                    "case_id": case.case_id,
                    "name": case.name,
                    "request_id": "-",
                    "ok": False,
                    "latency_ms": 0,
                    "error_type": error_type,
                    "warnings": ["health_check_case_crashed"],
                }
            )
            latencies.append(0)

    total_cases = len(cases)
    passed_cases = sum(1 for case in cases if case["ok"] is True)
    failed_cases = total_cases - passed_cases
    report: dict[str, object] = {
        "provider": settings.ai_provider,
        "model": settings.ai_model,
        "ran_at": ran_at.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "total_cases": total_cases,
        "passed_cases": passed_cases,
        "failed_cases": failed_cases,
        "pass": failed_cases == 0,
        "latency_ms_p50": _percentile_nearest_rank(latencies, 50),
        "latency_ms_p95": _percentile_nearest_rank(latencies, 95),
        "error_type_counts": error_type_counts,
        "cases": cases,
    }

    report_path = _report_path(
        root_dir=Path(settings.ai_raw_snapshot_dir),
        provider=settings.ai_provider,
        model=settings.ai_model,
        ran_at=ran_at,
    )
    report["report_path"] = str(report_path)

    try:
        _write_report(report_path, report)
    except Exception as exc:
        log_operation(
            "provider_health_check_report_write_failed",
            provider=settings.ai_provider,
            model=settings.ai_model,
            error_type=type(exc).__name__,
        )

    log_operation(
        "provider_health_check",
        provider=settings.ai_provider,
        model=settings.ai_model,
        total_cases=total_cases,
        failed_cases=failed_cases,
        latency_ms_p95=report["latency_ms_p95"],
        **{"pass": report["pass"]},
    )
    return report
