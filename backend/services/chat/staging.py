# backend/services/chat/staging.py
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import json


@dataclass(slots=True)
class ChatStagingRecord:
    request_id: str
    snapshot_id: str
    provider: str
    model: str
    context_pack_hash: str
    normalized_text: str
    public_text: str
    latency_ms: int
    gate_status: str
    dq_status: str
    gate_reasons: list[str]
    dq_reasons: list[str]
    warnings: list[str]
    demand_source: str
    triggered_retrieval: bool
    categories: list[str]
    top_k: int
    env: str
    has_context_pack: bool
    snapshot_dir: str
    created_at: str
    error_type: str | None = None


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def persist_chat_staging_record(
    *,
    snapshot_root_dir: str | Path,
    snapshot_dir: str | Path,
    record: ChatStagingRecord,
) -> dict[str, object]:
    payload = asdict(record)
    root_dir = Path(snapshot_root_dir)
    request_snapshot_dir = Path(snapshot_dir)
    request_id = record.request_id

    _write_json(root_dir / "_staging" / f"{request_id}.staging.json", payload)
    _write_json(request_snapshot_dir / "staging_record.json", payload)
    return payload


def persist_chat_quarantine_entry(
    *,
    snapshot_root_dir: str | Path,
    snapshot_dir: str | Path,
    record: ChatStagingRecord,
) -> dict[str, object]:
    payload = asdict(record)
    root_dir = Path(snapshot_root_dir)
    request_snapshot_dir = Path(snapshot_dir)
    request_id = record.request_id
    quarantine_dir = root_dir / "_quarantine"

    _write_json(quarantine_dir / f"{request_id}.quarantine.json", payload)
    _write_json(request_snapshot_dir / "quarantine_entry.json", payload)

    reasons = list(dict.fromkeys([*record.gate_reasons, *record.dq_reasons]))
    index_entry = {
        "request_id": record.request_id,
        "snapshot_id": record.snapshot_id,
        "provider": record.provider,
        "model": record.model,
        "error_type": record.error_type or "-",
        "gate_status": record.gate_status,
        "dq_status": record.dq_status,
        "reasons": reasons,
        "created_at": record.created_at,
    }
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    with (quarantine_dir / "quarantine_index.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(index_entry, ensure_ascii=False, sort_keys=True))
        handle.write("\n")

    return payload
