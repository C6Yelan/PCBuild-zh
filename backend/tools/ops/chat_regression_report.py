# backend/tools/ops/chat_regression_report.py
"""Compatibility wrapper for the stable chat regression report CLI module path."""
from __future__ import annotations

from typing import Sequence

from backend.services.chat.config import get_ai_settings
from backend.services.chat.health import run_provider_health_check
from backend.tools.ops.chat import chat_regression_report as _impl

_FILENAME_SAFE_RE = _impl._FILENAME_SAFE_RE
_sanitize_filename_component = _impl._sanitize_filename_component
_build_regression_report = _impl._build_regression_report
_write_report = _impl._write_report


def main(argv: Sequence[str] | None = None) -> int:
    _impl.get_ai_settings = get_ai_settings
    _impl.run_provider_health_check = run_provider_health_check
    return _impl.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
