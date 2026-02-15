from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)
    try:
        export_run_reports(Path(args.run_dir))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _parse_args(argv: Optional[list[str]]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="t6_export_run_reports")
    p.add_argument("--run-dir", required=True)
    return p.parse_args(argv)


def export_run_reports(run_dir: Path) -> dict[str, int]:
    resolved_run_dir = Path(run_dir).resolve()
    decisions = _load_jsonl(resolved_run_dir / "decisions.jsonl")
    skip_items = _load_skip_items(resolved_run_dir / "skip_plans_report.json")

    needs_registry_items = [item for item in skip_items if item.get("decision") == "needs_registry"]
    quarantine_items = [item for item in skip_items if item.get("decision") == "quarantine"]

    registry_payload = _build_group_payload(
        needs_registry_items,
        summary_key="needs_registry",
    )
    quarantine_payload = _build_group_payload(
        quarantine_items,
        summary_key="quarantine",
    )
    manual_rows = _build_manual_review_rows(decisions)

    _write_json(resolved_run_dir / "registry_todo.json", registry_payload)
    _write_json(resolved_run_dir / "quarantine_todo.json", quarantine_payload)
    _write_jsonl(resolved_run_dir / "manual_review.jsonl", manual_rows)

    summary = {
        "needs_registry": len(needs_registry_items),
        "quarantine": len(quarantine_items),
        "needs_manual_review": len(manual_rows),
    }
    print(
        f"[T6] reports: needs_registry={summary['needs_registry']} quarantine={summary['quarantine']} "
        f"needs_manual_review={summary['needs_manual_review']} -> {resolved_run_dir}",
        file=sys.stderr,
    )
    return summary


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            text = line.strip()
            if not text:
                continue
            row = json.loads(text)
            if isinstance(row, dict):
                out.append(row)
    return out


def _load_skip_items(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return []
    items = payload.get("items")
    if not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    for row in items:
        if isinstance(row, dict):
            out.append(row)
    return out


def _build_group_payload(items: list[dict[str, Any]], *, summary_key: str) -> dict[str, Any]:
    grouped: dict[tuple[str | None, str], list[dict[str, Any]]] = defaultdict(list)
    for row in items:
        brand_key = _normalize_brand_key(row.get("brand_key"))
        category = _to_text(row.get("category"))
        grouped[(brand_key, category)].append(
            {
                "plan_index": _to_int(row.get("plan_index"), default=-1),
                "retail_title": _to_text(row.get("retail_title") or row.get("title")),
                "retail_url": _to_text(row.get("retail_url") or row.get("url")),
            }
        )

    groups: list[dict[str, Any]] = []
    for brand_key, category in sorted(grouped.keys(), key=_group_sort_key):
        rows = grouped[(brand_key, category)]
        rows.sort(key=lambda x: (_to_int(x.get("plan_index"), default=-1), _to_text(x.get("retail_title")), _to_text(x.get("retail_url"))))
        groups.append(
            {
                "brand_key": brand_key,
                "category": category,
                "count": len(rows),
                "samples": rows[:3],
            }
        )

    return {
        "summary": {summary_key: len(items)},
        "groups": groups,
    }


def _build_manual_review_rows(decisions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in decisions:
        if _to_text(row.get("decision")) != "needs_manual_review":
            continue
        rows.append(
            {
                "plan_index": _to_int(row.get("plan_index"), default=-1),
                "retail_title": _to_text(row.get("retail_title") or row.get("title")),
                "retail_url": _to_text(row.get("retail_url") or row.get("url")),
                "decision": "needs_manual_review",
                "decision_reason": _to_text(row.get("decision_reason")),
                "matched_tokens": _to_str_list(row.get("matched_tokens")),
                "top_k_summary": row.get("top_k_summary") if isinstance(row.get("top_k_summary"), list) else [],
            }
        )
    rows.sort(key=lambda x: (_to_int(x.get("plan_index"), default=-1), _to_text(x.get("retail_url"))))
    return rows


def _group_sort_key(key: tuple[str | None, str]) -> tuple[int, str, str]:
    brand_key, category = key
    none_rank = 1 if brand_key is None else 0
    brand = brand_key.lower() if isinstance(brand_key, str) else ""
    return (none_rank, brand, category)


def _normalize_brand_key(value: Any) -> str | None:
    if isinstance(value, str):
        text = value.strip()
        return text if text else None
    return None


def _to_text(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if value is None:
        return ""
    return str(value).strip()


def _to_int(value: Any, *, default: int) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def _to_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str):
            out.append(item.strip())
    return out


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
