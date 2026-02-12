# backend/tools/crawler/official_reconcile_json.py
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Optional, cast

from backend.services.crawler.official_reconcile_gate.engine import reconcile_many
from backend.services.crawler.official_reconcile_gate.types import ListingInput


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)

    try:
        raw_items = _load_items(args.input)
    except (OSError, ValueError) as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 2

    items: list[ListingInput] = [cast(ListingInput, item) for item in raw_items]
    official_sources: list[str] = list(args.official_source or [])
    results, counters = reconcile_many(items, official_sources)

    try:
        with open(args.report, "w", encoding="utf-8") as out_f:
            for idx, result in enumerate(results):
                item = raw_items[idx] if idx < len(raw_items) else {}
                item_obj = item if isinstance(item, dict) else {}
                row = {
                    "source": item_obj.get("source", ""),
                    "category": item_obj.get("category", ""),
                    "title": item_obj.get("title", ""),
                    "url": item_obj.get("url", ""),
                    "sku_hint": item_obj.get("sku_hint", ""),
                    "t6": result,
                }
                out_f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    except OSError as exc:
        print(f"io error: {exc}", file=sys.stderr)
        return 2

    total = len(results)
    print(
        (
            f"total={total} "
            f"matched={counters.get('matched', 0)} "
            f"unmatched={counters.get('unmatched', 0)} "
            f"ambiguous={counters.get('ambiguous', 0)} "
            f"skip={counters.get('skip', 0)} "
            f"quarantine={counters.get('quarantine', 0)} "
            f"error={counters.get('error', 0)}"
        ),
        file=sys.stderr,
    )
    return 0


def _parse_args(argv: Optional[list[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="official_reconcile_json")
    parser.add_argument("--input", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--official-source", action="append", default=[])
    return parser.parse_args(argv)


def _load_items(path: str) -> list[Any]:
    with open(path, "r", encoding="utf-8") as f:
        first = _peek_first_non_ws_char(f)
        f.seek(0)

        if first in ("[", "{"):
            try:
                data = json.load(f)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"invalid JSON: {exc.msg} (line {exc.lineno}, col {exc.colno})"
                ) from exc

            if isinstance(data, dict):
                return [data]
            if isinstance(data, list):
                return data
            raise ValueError("JSON input must be an object or an array")

        items: list[Any] = []
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at line {lineno}: {exc.msg}") from exc
        return items


def _peek_first_non_ws_char(f) -> str:
    while True:
        ch = f.read(1)
        if ch == "":
            return ""
        if not ch.isspace():
            return ch


if __name__ == "__main__":
    raise SystemExit(main())
