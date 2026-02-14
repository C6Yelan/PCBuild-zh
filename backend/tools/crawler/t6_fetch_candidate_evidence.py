from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import Any, Iterator, Optional

from backend.services.crawler.official_reconcile_gate.evidence.fetch import (
    EvidenceFetchLimits,
    build_evidence_http_client,
    close_evidence_http_client,
    fetch_evidence,
)
from backend.services.crawler.official_reconcile_gate.evidence.types import EvidenceRecord, FetchResult
from backend.services.crawler.official_reconcile_gate.planning.registry import get_allowed_domains, load_official_registry


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)

    try:
        rows = list(_iter_input_rows(args.input))
        registry = load_official_registry(args.registry)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    limits = EvidenceFetchLimits(
        max_bytes=int(args.max_bytes),
        snippet_bytes=int(args.snippet_bytes),
        timeout_seconds=float(args.timeout_seconds),
        max_redirects=int(args.max_redirects),
    )
    if (
        limits.max_bytes <= 0
        or limits.snippet_bytes <= 0
        or limits.timeout_seconds <= 0
        or limits.max_redirects < 0
    ):
        print("error: invalid fetch limits", file=sys.stderr)
        return 2

    stats = {
        "total_candidates": 0,
        "to_fetch": 0,
        "skipped_robots": 0,
        "fetched_ok": 0,
        "fetched_truncated": 0,
        "fetched_http_error": 0,
        "fetched_unreachable": 0,
        "blocked_count": {},
        "bytes_read_total": 0,
        "errors_count": 0,
    }

    client = build_evidence_http_client(limits)
    try:
        with open(args.output, "w", encoding="utf-8") as out_f:
            for row in rows:
                stats["total_candidates"] += 1
                try:
                    evidence = _build_evidence_record(row, registry=registry, client=client, limits=limits, stats=stats)
                except Exception:
                    stats["errors_count"] += 1
                    evidence = _internal_error_record(row)
                out_f.write(json.dumps(asdict(evidence), ensure_ascii=False) + "\n")
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        close_evidence_http_client(client)

    _print_stats(stats)
    return 0


def _parse_args(argv: Optional[list[str]]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="t6_fetch_candidate_evidence")
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument(
        "--registry",
        default="backend/services/crawler/official_reconcile_gate/planning/data/official_registry.v1.json",
    )
    p.add_argument("--max-bytes", type=int, default=131072)
    p.add_argument("--snippet-bytes", type=int, default=4096)
    p.add_argument("--timeout-seconds", type=float, default=10.0)
    p.add_argument("--max-redirects", type=int, default=5)
    return p.parse_args(argv)


def _iter_input_rows(path: str) -> Iterator[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        first = _peek_first_non_ws_char(f)
        f.seek(0)
        if first == "[":
            payload = json.load(f)
            if not isinstance(payload, list):
                raise ValueError("input must be a JSON array or JSONL")
            for obj in payload:
                if not isinstance(obj, dict):
                    raise ValueError("each input row must be object")
                yield dict(obj)
            return

        for lineno, line in enumerate(f, start=1):
            text = line.strip()
            if not text:
                continue
            obj = json.loads(text)
            if not isinstance(obj, dict):
                raise ValueError(f"input row at line {lineno} must be object")
            yield dict(obj)


def _peek_first_non_ws_char(f) -> str:
    while True:
        ch = f.read(1)
        if ch == "":
            return ""
        if not ch.isspace():
            return ch


def _build_evidence_record(
    row: dict[str, Any],
    *,
    registry: Any,
    client: Any,
    limits: EvidenceFetchLimits,
    stats: dict[str, Any],
) -> EvidenceRecord:
    candidate_url = _pick_candidate_url(row)
    brand_key = _optional_str(row.get("brand_key"))
    retail_url = _optional_str(row.get("retail_url"))
    discovery_source = _extract_discovery_source(row)
    robots_allowed = bool(row.get("robots_allowed", False))
    robots_reason = _optional_str(row.get("robots_reason"))

    if not robots_allowed:
        stats["skipped_robots"] += 1
        return EvidenceRecord(
            candidate_url=candidate_url,
            brand_key=brand_key,
            retail_url=retail_url,
            discovery_source=discovery_source,
            robots_allowed=False,
            robots_reason=robots_reason,
            fetch_status="skipped_robots",
            http_status_code=None,
            final_url=None,
            content_type=None,
            content_length=None,
            content_range=None,
            server=None,
            cache_control=None,
            body_sha256=None,
            body_snippet="",
            block_reason=None,
        )

    stats["to_fetch"] += 1
    allowed_hosts = _resolve_allowed_hosts(row, registry=registry, brand_key=brand_key)
    result = fetch_evidence(
        candidate_url,
        client,
        limits,
        allowed_hosts=allowed_hosts,
    )
    _accumulate_fetch_stats(stats, result)

    return EvidenceRecord(
        candidate_url=candidate_url,
        brand_key=brand_key,
        retail_url=retail_url,
        discovery_source=discovery_source,
        robots_allowed=True,
        robots_reason=robots_reason,
        fetch_status=result.fetch_status,
        http_status_code=result.http_status_code,
        final_url=result.final_url,
        content_type=result.content_type,
        content_length=result.content_length,
        content_range=result.content_range,
        server=result.server,
        cache_control=result.cache_control,
        body_sha256=result.body_sha256,
        body_snippet=result.body_snippet,
        block_reason=result.block_reason,
    )


def _pick_candidate_url(row: dict[str, Any]) -> str:
    for key in ("official_url", "candidate_url", "url"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _extract_discovery_source(row: dict[str, Any]) -> str | None:
    evidence = row.get("evidence")
    if isinstance(evidence, dict):
        source = evidence.get("discovery_source")
        if isinstance(source, str) and source.strip():
            return source.strip()
    return None


def _resolve_allowed_hosts(row: dict[str, Any], *, registry: Any, brand_key: str | None) -> set[str]:
    domains: list[str] = []
    if brand_key:
        domains = get_allowed_domains(registry, brand_key)
    if not domains:
        raw_domains = row.get("allowed_domains")
        if isinstance(raw_domains, list):
            domains = [d for d in raw_domains if isinstance(d, str)]
    return {d.strip().lower() for d in domains if isinstance(d, str) and d.strip()}


def _optional_str(value: Any) -> str | None:
    if isinstance(value, str):
        text = value.strip()
        return text if text else None
    return None


def _accumulate_fetch_stats(stats: dict[str, Any], result: FetchResult) -> None:
    stats["bytes_read_total"] += int(result.bytes_read)
    http_status_code = result.http_status_code if isinstance(result.http_status_code, int) else None
    is_truncated_success = result.fetch_status == "too_large" and http_status_code in (200, 206)

    if result.fetch_status == "fetched" or is_truncated_success:
        stats["fetched_ok"] += 1
    if result.fetch_status == "too_large":
        stats["fetched_truncated"] += 1

    if result.fetch_status == "http_error" or (http_status_code is not None and http_status_code >= 400):
        stats["fetched_http_error"] += 1
    elif result.fetch_status in ("unreachable", "invalid_url"):
        stats["fetched_unreachable"] += 1

    if result.block_reason:
        block_count = stats["blocked_count"]
        block_count[result.block_reason] = block_count.get(result.block_reason, 0) + 1


def _internal_error_record(row: dict[str, Any]) -> EvidenceRecord:
    return EvidenceRecord(
        candidate_url=_pick_candidate_url(row),
        brand_key=_optional_str(row.get("brand_key")),
        retail_url=_optional_str(row.get("retail_url")),
        discovery_source=_extract_discovery_source(row),
        robots_allowed=bool(row.get("robots_allowed", False)),
        robots_reason=_optional_str(row.get("robots_reason")),
        fetch_status="unreachable",
        http_status_code=None,
        final_url=None,
        content_type=None,
        content_length=None,
        content_range=None,
        server=None,
        cache_control=None,
        body_sha256=None,
        body_snippet="",
        block_reason=None,
    )


def _print_stats(stats: dict[str, Any]) -> None:
    print(
        f"total_candidates={stats['total_candidates']} to_fetch={stats['to_fetch']} skipped_robots={stats['skipped_robots']}",
        file=sys.stderr,
    )
    print(
        f"fetched_ok={stats['fetched_ok']} fetched_truncated={stats['fetched_truncated']} fetched_http_error={stats['fetched_http_error']} fetched_unreachable={stats['fetched_unreachable']}",
        file=sys.stderr,
    )
    block_count = stats["blocked_count"]
    if block_count:
        block_summary = ",".join(f"{k}:{block_count[k]}" for k in sorted(block_count))
    else:
        block_summary = "none"
    print(f"blocked_count={block_summary}", file=sys.stderr)
    print(f"bytes_read_total={stats['bytes_read_total']}", file=sys.stderr)
    print(f"errors_count={stats['errors_count']}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
