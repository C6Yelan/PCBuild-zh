"""Compatibility wrapper for the stable chat release check CLI module path."""
from __future__ import annotations

from typing import Sequence

from backend.tools.ops.chat import chat_release_check as _impl
from backend.tools.ops.chat.chat_artifact_helpers import emit_json_payload, read_json_artifact

run_p10_release_check = _impl.run_p10_release_check


def main(argv: Sequence[str] | None = None) -> int:
    _impl.run_p10_release_check = run_p10_release_check
    _impl.emit_json_payload = emit_json_payload
    _impl.read_json_artifact = read_json_artifact
    return _impl.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
