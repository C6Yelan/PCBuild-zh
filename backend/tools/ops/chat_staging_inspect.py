"""Official chat ops CLI: inspect staging and quarantine artifacts."""

# backend/tools/ops/chat_staging_inspect.py
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from backend.services.chat.config import get_ai_settings
from backend.services.chat.snapshot_store import read_json_file, snapshot_root


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
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    if not args.request_id:
        parser.error("--request-id is required unless --list-quarantine is used")

    snapshot_dir = root / args.request_id
    if not snapshot_dir.is_dir():
        print(f"snapshot not found: {snapshot_dir}")
        return 2

    payload: dict[str, object] = {
        "request_id": args.request_id,
        "snapshot_dir": str(snapshot_dir),
        "artifacts": sorted(path.name for path in snapshot_dir.iterdir() if path.is_file()),
    }
    if (snapshot_dir / "meta.json").is_file():
        payload["meta"] = read_json_file(snapshot_dir / "meta.json")
    if (snapshot_dir / "staging_record.json").is_file():
        payload["staging_record"] = read_json_file(snapshot_dir / "staging_record.json")
    if (snapshot_dir / "quarantine_entry.json").is_file():
        payload["quarantine_entry"] = read_json_file(snapshot_dir / "quarantine_entry.json")

    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))

    if "staging_record" in payload or "quarantine_entry" in payload:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
