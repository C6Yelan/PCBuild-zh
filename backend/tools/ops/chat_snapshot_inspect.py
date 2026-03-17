# backend/tools/ops/chat_snapshot_inspect.py
"""Compatibility wrapper for the stable chat snapshot inspect CLI module path."""
from __future__ import annotations

from typing import Sequence

from backend.services.chat.config import get_ai_settings
from backend.services.chat.snapshot_store import snapshot_dir as snapshot_dir_for_request
from backend.tools.ops.chat import chat_snapshot_inspect as _impl
from backend.tools.ops.chat.chat_artifact_helpers import (
    build_request_snapshot_payload,
    emit_json_payload,
)

_REQUIRED_FILES = _impl._REQUIRED_FILES
_SNAPSHOT_ARTIFACT_SPECS = _impl._SNAPSHOT_ARTIFACT_SPECS


def main(argv: Sequence[str] | None = None) -> int:
    _impl.get_ai_settings = get_ai_settings
    _impl.snapshot_dir_for_request = snapshot_dir_for_request
    _impl.build_request_snapshot_payload = build_request_snapshot_payload
    _impl.emit_json_payload = emit_json_payload
    return _impl.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
