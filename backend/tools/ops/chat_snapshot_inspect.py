"""Official chat ops CLI: inspect snapshot artifacts by request ID."""

# backend/tools/ops/chat_snapshot_inspect.py
from __future__ import annotations

import argparse
from typing import Sequence

from backend.services.chat.config import get_ai_settings
from backend.services.chat.snapshot_store import snapshot_dir as snapshot_dir_for_request
from backend.tools.ops.chat_artifact_helpers import (
    build_request_snapshot_payload,
    emit_json_payload,
)


_REQUIRED_FILES = (
    "raw_request.json",
    "raw_response.json",
    "meta.json",
    "request_context.json",
)

_SNAPSHOT_ARTIFACT_SPECS = (
    ("meta", "meta.json"),
    ("request_context", "request_context.json"),
    ("lineage", "lineage.json"),
    ("validation_report", "validation_report.json"),
    ("dq_report", "dq_report.json"),
    ("staging_record", "staging_record.json"),
    ("quarantine_entry", "quarantine_entry.json"),
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
    payload = build_request_snapshot_payload(
        request_id=args.request_id,
        snapshot_dir=snapshot_dir,
        artifact_specs=_SNAPSHOT_ARTIFACT_SPECS,
    )

    emit_json_payload(payload)

    if missing_files:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
