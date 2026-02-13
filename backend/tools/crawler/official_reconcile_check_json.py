# backend/tools/crawler/official_reconcile_check_json.py
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from backend.services.crawler.official_reconcile_gate.types import RetailRecord


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)
    from backend.services.crawler.official_reconcile_gate.engine import OfficialReconcileEngine

    try:
        rows, input_format = _load_input_rows(args.input)
    except (OSError, ValueError) as e:
        print(f"Input error: {e}", file=sys.stderr)
        return 2

    if args.max_items is not None and args.max_items < 0:
        print("Input error: --max-items must be >= 0", file=sys.stderr)
        return 2

    limit = args.max_items if args.max_items is not None else len(rows)
    selected = rows[:limit]

    canonical_records: list[dict[str, Any]] = []
    report_rows: list[dict[str, Any]] = []

    try:
        with OfficialReconcileEngine(
            timeout_seconds=float(args.timeout_s),
            user_agent=args.user_agent,
            max_redirects=int(args.max_redirects),
        ) as engine:
            for obj, where in selected:
                listing = _parse_listing(obj, where=where)
                result = engine.reconcile_one(listing, raw_record=obj)

                canonical_records.append(result.canonical_record)
                report_rows.append(
                    {
                        "key": result.row.key,
                        "status": result.row.status,
                        "official_url": result.row.official_url,
                        "diff_count": result.row.diff_count,
                        "diff_entries": [asdict(d) for d in result.diffs],
                        "patch_count": result.row.patch_count,
                        "error": result.row.error,
                        "audit": asdict(result.audit),
                    }
                )

        _write_rows(args.output, canonical_records, fmt=input_format)
        _write_rows(args.report, report_rows, fmt=input_format)
    except ValueError as e:
        print(f"Input error: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"IO error: {e}", file=sys.stderr)
        return 2

    # Fetch/extract failures are represented inside report rows and still return 0.
    return 0


def _parse_args(argv: Optional[list[str]]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="official_reconcile_check_json",
        description=(
            "Run T6 official reconciliation skeleton over JSON array/NDJSON. "
            "Canonical output keeps input shape, report contains per-row status/diff/patch summary."
        ),
    )
    p.add_argument("--input", required=True, help="Input file path (JSON array or NDJSON)")
    p.add_argument("--output", required=True, help="Canonical output file path")
    p.add_argument("--report", required=True, help="Reconciliation report file path")
    p.add_argument("--max-items", type=int, default=None, help="Only process first N items")
    p.add_argument("--timeout-s", type=float, default=5.0, help="HTTP timeout seconds (default: 5)")
    p.add_argument("--max-redirects", type=int, default=5, help="HTTP max redirects")
    p.add_argument("--user-agent", default=None, help="Override crawler User-Agent")
    return p.parse_args(argv)


def _load_input_rows(path: str) -> tuple[list[tuple[dict[str, Any], str]], str]:
    rows: list[tuple[dict[str, Any], str]] = []
    with open(path, "r", encoding="utf-8") as f:
        first = _peek_first_non_ws_char(f)
        f.seek(0)

        if first == "[":
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"invalid JSON: {e.msg} (pos {e.pos})") from e
            if not isinstance(data, list):
                raise ValueError("JSON input must be an array when using JSON mode")
            for idx, obj in enumerate(data):
                if not isinstance(obj, dict):
                    raise ValueError(f"expected object at index {idx}, got {type(obj).__name__}")
                rows.append((obj, f"index {idx}"))
            return rows, "json_array"

        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"invalid JSONL at line {lineno}: {e.msg}") from e
            if not isinstance(obj, dict):
                raise ValueError(f"expected object at line {lineno}, got {type(obj).__name__}")
            rows.append((obj, f"line {lineno}"))
    return rows, "ndjson"


def _peek_first_non_ws_char(f) -> str:
    while True:
        ch = f.read(1)
        if ch == "":
            return ""
        if not ch.isspace():
            return ch


def _write_rows(path: str, rows: list[dict[str, Any]], *, fmt: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        if fmt == "json_array":
            json.dump(rows, f, ensure_ascii=False, indent=2)
            f.write("\n")
            return

        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _parse_listing(obj: dict[str, Any], *, where: str) -> "RetailRecord":
    from backend.services.crawler.official_reconcile_gate.types import RetailRecord

    source = _req_str(obj, "source", where=where)
    category = _req_str(obj, "category", where=where)
    title = _req_str(obj, "title", where=where)
    url = _req_str(obj, "url", where=where)

    sku_hint_val = obj.get("sku_hint", "")
    if sku_hint_val is None:
        raise ValueError(f"sku_hint must not be null at {where}")
    if not isinstance(sku_hint_val, str):
        raise ValueError(f"sku_hint must be string at {where}")

    extra_val = obj.get("extra", {})
    if extra_val is None:
        extra_val = {}
    if not isinstance(extra_val, dict):
        raise ValueError(f"extra must be object at {where}")
    extra: dict[str, Any] = dict(extra_val)

    for k, v in obj.items():
        if k in ("source", "category", "title", "url", "sku_hint", "extra"):
            continue
        extra.setdefault(k, v)

    return RetailRecord(
        source=source,
        category=category,
        title=title,
        url=url,
        sku_hint=sku_hint_val,
        extra=extra,
    )


def _req_str(obj: dict[str, Any], key: str, *, where: str) -> str:
    if key not in obj:
        raise ValueError(f"missing required field {key!r} at {where}")
    val = obj[key]
    if not isinstance(val, str):
        raise ValueError(f"field {key!r} must be string at {where}")
    return val


if __name__ == "__main__":
    raise SystemExit(main())
