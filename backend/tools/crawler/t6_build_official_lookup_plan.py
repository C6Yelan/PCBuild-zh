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
        report_path = Path(args.output).resolve().parent / "skip_plans_report.json"
        report = _build_skip_plans_report(plans)
        _write_skip_plans_report(report_path, report)
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


def _build_skip_plans_report(plans: list[Any]) -> dict[str, Any]:
    summary = {
        "total_plans": len(plans),
        "ok": 0,
        "needs_registry": 0,
        "quarantine": 0,
    }
    items: list[dict[str, Any]] = []

    for idx, plan in enumerate(plans):
        decision = str(getattr(plan, "decision", "")).strip()
        if decision in summary:
            summary[decision] += 1
        if decision not in {"needs_registry", "quarantine"}:
            continue

        brand_key = getattr(plan, "brand_key", None)
        if isinstance(brand_key, str):
            brand_key = brand_key.strip() or None
        else:
            brand_key = None

        category = getattr(plan, "category", "")
        retail_title = getattr(plan, "title", "")
        retail_url = getattr(plan, "retail_url", "")
        notes = getattr(plan, "decision_notes", "")

        items.append(
            {
                "plan_index": idx,
                "decision": decision,
                "brand_key": brand_key,
                "category": str(category).strip(),
                "retail_title": str(retail_title).strip(),
                "retail_url": str(retail_url).strip(),
                "notes": str(notes).strip(),
            }
        )

    items.sort(key=_skip_item_sort_key)
    return {"summary": summary, "items": items}


def _skip_item_sort_key(item: dict[str, Any]) -> tuple[int, int, str, str, int]:
    decision_order = {"needs_registry": 0, "quarantine": 1}
    decision = str(item.get("decision", "")).strip()
    decision_rank = decision_order.get(decision, 99)

    brand_key_raw = item.get("brand_key")
    brand_key = brand_key_raw if isinstance(brand_key_raw, str) else ""
    has_no_brand = 1 if not brand_key else 0

    category_raw = item.get("category")
    category = category_raw.strip() if isinstance(category_raw, str) else ""

    plan_index_raw = item.get("plan_index")
    plan_index = int(plan_index_raw) if isinstance(plan_index_raw, int) else 0
    return (decision_rank, has_no_brand, brand_key.lower(), category, plan_index)


def _write_skip_plans_report(path: Path, report: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
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
