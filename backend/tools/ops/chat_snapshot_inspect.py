"""Official chat ops CLI: inspect snapshot artifacts by request ID."""

# backend/tools/ops/chat_snapshot_inspect.py
from __future__ import annotations

import argparse
import json
from typing import Sequence

from backend.services.chat.config import get_ai_settings
from backend.services.chat.snapshot_store import (
    read_json_file,
    snapshot_dir as snapshot_dir_for_request,
)


_REQUIRED_FILES = (
    "raw_request.json",
    "raw_response.json",
    "meta.json",
    "request_context.json",
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect chat snapshot artifacts by request ID.")
    parser.add_argument("--request-id", required=True)
    args = parser.parse_args(argv)

    snapshot_dir = snapshot_dir_for_request(get_ai_settings(), args.request_id)
    if not snapshot_dir.is_dir():
        print(f"snapshot not found: {snapshot_dir}")
        return 2

    missing_files = [
        filename for filename in _REQUIRED_FILES if not (snapshot_dir / filename).is_file()
    ]
    artifacts = sorted(path.name for path in snapshot_dir.iterdir() if path.is_file())

    payload: dict[str, object] = {
        "request_id": args.request_id,
        "snapshot_dir": str(snapshot_dir),
        "artifacts": artifacts,
    }

    if (snapshot_dir / "meta.json").is_file():
        payload["meta"] = read_json_file(snapshot_dir / "meta.json")
    if (snapshot_dir / "request_context.json").is_file():
        payload["request_context"] = read_json_file(snapshot_dir / "request_context.json")
    if (snapshot_dir / "lineage.json").is_file():
        payload["lineage"] = read_json_file(snapshot_dir / "lineage.json")
    if (snapshot_dir / "validation_report.json").is_file():
        payload["validation_report"] = read_json_file(snapshot_dir / "validation_report.json")
    if (snapshot_dir / "dq_report.json").is_file():
        payload["dq_report"] = read_json_file(snapshot_dir / "dq_report.json")
    if (snapshot_dir / "staging_record.json").is_file():
        payload["staging_record"] = read_json_file(snapshot_dir / "staging_record.json")
    if (snapshot_dir / "quarantine_entry.json").is_file():
        payload["quarantine_entry"] = read_json_file(snapshot_dir / "quarantine_entry.json")

    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))

    if missing_files:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
