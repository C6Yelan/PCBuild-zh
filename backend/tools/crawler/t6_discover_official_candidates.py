from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

from backend.services.crawler.official_reconcile_gate.discovery.discover import (
    discover_candidates_from_plans,
)
from backend.services.crawler.official_reconcile_gate.planning.registry import (
    load_official_registry,
)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)

    try:
        plans = _load_json_array(args.plans)
        registry = load_official_registry(args.registry)
        result = discover_candidates_from_plans(
            plans,
            registry=registry,
            max_sitemaps_per_domain=int(args.max_sitemaps_per_domain),
            topk=int(args.topk),
            min_score=int(args.min_score),
            timeout_seconds=float(args.timeout_seconds),
            max_bytes=int(args.max_bytes),
            max_redirects=int(args.max_redirects),
        )
        _write_candidates_jsonl(args.output, result.candidates)
        _print_stats(result)
    except (ValueError, OSError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
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
    p = argparse.ArgumentParser(prog="t6_discover_official_candidates")
    p.add_argument("--plans", required=True, help="Phase A plans JSON array path")
    p.add_argument("--output", required=True, help="discovery candidates JSONL path")
    p.add_argument("--registry", default=str(default_registry), help="official registry path")
    p.add_argument("--max-sitemaps-per-domain", type=int, default=10)
    p.add_argument("--topk", type=int, default=5)
    p.add_argument("--min-score", type=int, default=1)
    p.add_argument("--timeout-seconds", type=float, default=10.0)
    p.add_argument("--max-bytes", type=int, default=5_242_880)
    p.add_argument("--max-redirects", type=int, default=5)
    return p.parse_args(argv)


def _load_json_array(path: str) -> list[Any]:
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, list):
        raise ValueError("plans must be a JSON array")
    return payload


def _write_candidates_jsonl(path: str, candidates: list[Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for candidate in candidates:
            f.write(json.dumps(asdict(candidate), ensure_ascii=False) + "\n")


def _print_stats(result: Any) -> None:
    print(
        f"total_plans={result.total_plans} ok_plans={result.ok_plans} skipped_plans={result.skipped_plans}",
        file=sys.stderr,
    )
    print(
        f"seeds_used_count={result.seeds_used_count} default_entrypoints_used_count={result.default_entrypoints_used_count}",
        file=sys.stderr,
    )
    print(
        f"plans_with_hits={result.plans_with_hits} plans_no_hits={result.plans_no_hits}",
        file=sys.stderr,
    )
    print(
        f"fetched_sitemaps={result.fetched_sitemaps} parsed_urlsets={result.parsed_urlsets} parsed_indexes={result.parsed_indexes}",
        file=sys.stderr,
    )
    print(f"total_candidates_emitted={result.total_candidates_emitted}", file=sys.stderr)
    reason_summary = _format_error_reasons(result.error_reasons)
    print(f"errors_count={result.errors_count} reasons={reason_summary}", file=sys.stderr)


def _format_error_reasons(error_reasons: dict[str, int]) -> str:
    if not error_reasons:
        return "none"
    return ",".join(f"{key}:{error_reasons[key]}" for key in sorted(error_reasons))


if __name__ == "__main__":
    raise SystemExit(main())
