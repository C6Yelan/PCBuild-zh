"""Compatibility wrapper for the stable chat staging inspect CLI module path."""
from __future__ import annotations

from typing import Sequence

from backend.services.chat.config import get_ai_settings
from backend.services.chat.snapshot_store import snapshot_root
from backend.tools.ops.chat import chat_staging_inspect as _impl
from backend.tools.ops.chat.chat_artifact_helpers import (
    build_request_snapshot_payload,
    emit_json_payload,
)

_STAGING_ARTIFACT_SPECS = _impl._STAGING_ARTIFACT_SPECS
_tail_jsonl = _impl._tail_jsonl


def main(argv: Sequence[str] | None = None) -> int:
    _impl.get_ai_settings = get_ai_settings
    _impl.snapshot_root = snapshot_root
    _impl.build_request_snapshot_payload = build_request_snapshot_payload
    _impl.emit_json_payload = emit_json_payload
    return _impl.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
