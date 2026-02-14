# backend/tools/crawler/t6_build_official_lookup_plan.py
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

from backend.services.crawler.official_reconcile_gate.planning.planner import build_official_lookup_plans
from backend.services.crawler.official_reconcile_gate.planning.registry import load_official_registry


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)

    try:
        rows = _load_input_rows(args.input)
        registry = load_official_registry(args.registry)
        plans = build_official_lookup_plans(rows, registry)
        _write_output(args.output, plans)
        _print_stats(plans)
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    return 0


def _parse_args(argv: Optional[list[str]]) -> argparse.Namespace:
    default_registry = (
        Path(__file__).resolve().parents[2]
        / "services"
        / "crawler"
        / "official_reconcile_gate"
        / "planning"
        / "data"
        / "official_registry.v1.json"
    )
    p = argparse.ArgumentParser(prog="t6_build_official_lookup_plan")
    p.add_argument("--input", required=True, help="input JSON array path")
    p.add_argument("--output", required=True, help="output JSON array path")
    p.add_argument(
        "--registry",
        default=str(default_registry),
        help="official registry path",
    )
    return p.parse_args(argv)


def _load_input_rows(path: str) -> list[Any]:
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, list):
        raise ValueError("input must be a JSON array")
    return payload


def _write_output(path: str, plans: list[Any]) -> None:
    payload = [asdict(plan) for plan in plans]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")


def _print_stats(plans: list[Any]) -> None:
    total = len(plans)
    ok = sum(1 for p in plans if p.decision == "ok")
    needs_registry = sum(1 for p in plans if p.decision == "needs_registry")
    quarantine = sum(1 for p in plans if p.decision == "quarantine")
    print(
        f"total={total} ok={ok} needs_registry={needs_registry} quarantine={quarantine}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    raise SystemExit(main())
