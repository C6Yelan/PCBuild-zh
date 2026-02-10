# backend/tools/crawler/link_consistency_check_json.py
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import Any, Iterator, Optional

from backend.services.crawler.link_consistency_gate.engine import LinkCheckEngine
from backend.services.crawler.link_consistency_gate.types import (
    BlockDetectionConfig,
    EngineConfig,
    FetchConfig,
    ListingInput,
    PacingConfig,
)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)

    try:
        rows = _iter_input_rows(args.input)
    except Exception as e:
        print(f"Input error: {e}", file=sys.stderr)
        return 2

    config = EngineConfig(
        fetch=FetchConfig(
            timeout_s=float(args.timeout_s),
            max_redirects=int(args.max_redirects),
            max_bytes=int(args.max_bytes),
        ),
        pacing=PacingConfig(
            min_interval_ms=int(args.min_interval_ms),
            jitter_ms=0,
        ),
        block=BlockDetectionConfig(
            enabled=bool(args.block_pattern),
            patterns=list(args.block_pattern or []),
        ),
    )

    try:
        with LinkCheckEngine(config) as engine, open(args.output, "w", encoding="utf-8") as out_f:
            for obj, where in rows:
                listing = _parse_listing(obj, where=where)
                report = engine.check_one(listing)
                payload = asdict(report)
                if payload.get("error") is None:
                    payload.pop("error", None)
                out_f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except ValueError as e:
        print(f"Input error: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"IO error: {e}", file=sys.stderr)
        return 2

    return 0


def _parse_args(argv: Optional[list[str]]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="link_consistency_check_json")
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--min-interval-ms", default=1000, type=int)
    p.add_argument("--timeout-s", default=10, type=float)
    p.add_argument("--max-redirects", default=5, type=int)
    p.add_argument("--max-bytes", default=1048576, type=int)
    p.add_argument("--block-pattern", action="append", default=[])
    return p.parse_args(argv)


def _iter_input_rows(path: str) -> Iterator[tuple[Any, str]]:
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
                yield obj, f"index {idx}"
            return

        # JSONL fallback.
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"invalid JSONL at line {lineno}: {e.msg}") from e
            yield obj, f"line {lineno}"


def _peek_first_non_ws_char(f) -> str:
    while True:
        ch = f.read(1)
        if ch == "":
            return ""
        if not ch.isspace():
            return ch


def _parse_listing(obj: Any, *, where: str) -> ListingInput:
    if not isinstance(obj, dict):
        raise ValueError(f"expected object at {where}, got {type(obj).__name__}")

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

    return ListingInput(
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
