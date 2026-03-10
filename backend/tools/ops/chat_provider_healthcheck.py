"""Official chat ops CLI: provider smoke and health check."""

# backend/tools/ops/chat_provider_healthcheck.py
from __future__ import annotations

import json

from backend.services.chat.health import run_provider_health_check


def main() -> int:
    report = run_provider_health_check()
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if bool(report.get("pass")) else 2


if __name__ == "__main__":
    raise SystemExit(main())
