# backend/tools/ops/chat_snapshot_inspect.py
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from backend.services.chat.config import get_ai_settings


_REQUIRED_FILES = (
    "raw_request.json",
    "raw_response.json",
    "meta.json",
    "request_context.json",
)


def _snapshot_dir(request_id: str) -> Path:
    settings = get_ai_settings()
    return Path(settings.ai_raw_snapshot_dir) / request_id


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect chat snapshot artifacts by request ID.")
    parser.add_argument("--request-id", required=True)
    args = parser.parse_args(argv)

    snapshot_dir = _snapshot_dir(args.request_id)
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
        payload["meta"] = _load_json(snapshot_dir / "meta.json")
    if (snapshot_dir / "request_context.json").is_file():
        payload["request_context"] = _load_json(snapshot_dir / "request_context.json")
    if (snapshot_dir / "lineage.json").is_file():
        payload["lineage"] = _load_json(snapshot_dir / "lineage.json")

    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))

    if missing_files:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
