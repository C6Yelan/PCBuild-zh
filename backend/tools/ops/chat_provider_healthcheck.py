"""Compatibility wrapper for the stable chat provider healthcheck CLI module path."""
from __future__ import annotations

from backend.services.chat.health import run_provider_health_check
from backend.tools.ops.chat import chat_provider_healthcheck as _impl


def main() -> int:
    _impl.run_provider_health_check = run_provider_health_check
    return _impl.main()


if __name__ == "__main__":
    raise SystemExit(main())
