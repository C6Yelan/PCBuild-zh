# backend/tools/ops/chat/chat_staging_inspect.py
"""Official chat ops CLI: inspect staging and quarantine artifacts."""

# backend/tools/ops/chat_staging_inspect.py
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from backend.services.chat.config import get_ai_settings
from backend.services.chat.snapshot_store import snapshot_root
from backend.tools.ops.chat.chat_artifact_helpers import (
    build_request_snapshot_payload,
    emit_json_payload,
)

_STAGING_ARTIFACT_SPECS = (
    ("meta", "meta.json"),
    ("staging_record", "staging_record.json"),
    ("quarantine_entry", "quarantine_entry.json"),
)


def _tail_jsonl(path: Path, limit: int) -> list[dict[str, object]]:
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    entries: list[dict[str, object]] = []
    for line in lines[-limit:]:
        if not line.strip():
            continue
        entries.append(json.loads(line))
    return entries


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect chat staging/quarantine artifacts.")
    parser.add_argument("--request-id")
    parser.add_argument("--list-quarantine", action="store_true")
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args(argv)

    root = snapshot_root(get_ai_settings())

    if args.list_quarantine:
        payload = {
            "entries": _tail_jsonl(root / "_quarantine" / "quarantine_index.jsonl", args.limit),
        }
        emit_json_payload(payload)
        return 0

    if not args.request_id:
        parser.error("--request-id is required unless --list-quarantine is used")

    snapshot_dir = root / args.request_id
    if not snapshot_dir.is_dir():
        print(f"snapshot not found: {snapshot_dir}")
        return 2

    payload = build_request_snapshot_payload(
        request_id=args.request_id,
        snapshot_dir=snapshot_dir,
        artifact_specs=_STAGING_ARTIFACT_SPECS,
    )

    emit_json_payload(payload)

    if "staging_record" in payload or "quarantine_entry" in payload:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
