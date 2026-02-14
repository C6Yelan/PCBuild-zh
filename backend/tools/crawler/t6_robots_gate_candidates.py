from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import time
from dataclasses import dataclass
from typing import Any, Iterator, Optional
from urllib.parse import urlsplit

from backend.services.crawler.official_reconcile_gate.planning.registry import (
    get_allowed_domains,
    load_official_registry,
)
from backend.services.crawler.official_reconcile_gate.robots.fetch import (
    RobotsFetchLimits,
    build_robots_http_client,
    close_robots_http_client,
    fetch_robots_txt,
)
from backend.services.crawler.official_reconcile_gate.robots.matcher import (
    has_matching_group,
    is_allowed,
)
from backend.services.crawler.official_reconcile_gate.robots.types import RobotsFetchResult

_UA_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$", flags=re.UNICODE)


@dataclass
class _GateStats:
    total_candidates: int = 0
    allowed: int = 0
    disallowed: int = 0
    robots_cache_hits: int = 0
    robots_cache_misses: int = 0
    fetch_success: int = 0
    fetch_unavailable: int = 0
    fetch_unreachable: int = 0
    fetch_parse_error: int = 0
    errors_count: int = 0


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)
    if not _UA_TOKEN_RE.fullmatch(args.user_agent_token):
        print("error: --user-agent-token is invalid RFC 9309 product token", file=sys.stderr)
        return 2

    try:
        registry = load_official_registry(args.registry)
        candidates = list(_iter_candidates(args.candidates))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    limits = RobotsFetchLimits(
        timeout_seconds=float(args.timeout_seconds),
        max_bytes=int(args.max_bytes),
        max_redirects=int(args.max_redirects),
    )
    if limits.timeout_seconds <= 0 or limits.max_bytes < 512_000 or limits.max_redirects < 0:
        print("error: invalid fetch limits", file=sys.stderr)
        return 2

    stats = _GateStats()
    cache_max_age_seconds = int(args.cache_max_age_seconds)
    cache: dict[tuple[str, str], RobotsFetchResult] = {}
    client = build_robots_http_client(limits)

    try:
        with open(args.output, "w", encoding="utf-8") as out_f:
            for obj in candidates:
                stats.total_candidates += 1
                try:
                    gated = _gate_one_candidate(
                        obj,
                        registry=registry,
                        user_agent_token=args.user_agent_token,
                        client=client,
                        limits=limits,
                        cache=cache,
                        cache_max_age_seconds=cache_max_age_seconds,
                        stats=stats,
                    )
                except Exception:
                    stats.errors_count += 1
                    gated = _mark_internal_error(obj)
                if gated["robots_allowed"]:
                    stats.allowed += 1
                else:
                    stats.disallowed += 1
                out_f.write(json.dumps(gated, ensure_ascii=False) + "\n")
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        close_robots_http_client(client)

    _print_stats(stats)
    return 0


def _parse_args(argv: Optional[list[str]]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="t6_robots_gate_candidates")
    p.add_argument("--candidates", required=True)
    p.add_argument("--output", required=True)
    p.add_argument(
        "--registry",
        default="backend/services/crawler/official_reconcile_gate/planning/data/official_registry.v1.json",
    )
    p.add_argument("--user-agent-token", default="PCBuildBot")
    p.add_argument("--timeout-seconds", type=float, default=10.0)
    p.add_argument("--max-bytes", type=int, default=512_000)
    p.add_argument("--max-redirects", type=int, default=5)
    p.add_argument("--cache-max-age-seconds", type=int, default=86_400)
    return p.parse_args(argv)


def _iter_candidates(path: str) -> Iterator[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        first = _peek_first_non_ws_char(f)
        f.seek(0)
        if first == "[":
            payload = json.load(f)
            if not isinstance(payload, list):
                raise ValueError("candidates JSON must be an array")
            for obj in payload:
                if not isinstance(obj, dict):
                    raise ValueError("candidate row must be object")
                yield dict(obj)
            return

        for lineno, line in enumerate(f, start=1):
            text = line.strip()
            if not text:
                continue
            obj = json.loads(text)
            if not isinstance(obj, dict):
                raise ValueError(f"candidate row must be object at line {lineno}")
            yield dict(obj)


def _peek_first_non_ws_char(f) -> str:
    while True:
        ch = f.read(1)
        if ch == "":
            return ""
        if not ch.isspace():
            return ch


def _gate_one_candidate(
    candidate: dict[str, Any],
    *,
    registry: Any,
    user_agent_token: str,
    client: Any,
    limits: RobotsFetchLimits,
    cache: dict[tuple[str, str], RobotsFetchResult],
    cache_max_age_seconds: int,
    stats: _GateStats,
) -> dict[str, Any]:
    out = dict(candidate)
    target_url = _extract_candidate_url(candidate)
    parsed = urlsplit(target_url)
    host = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()

    allowed_hosts = _resolve_allowed_hosts(candidate, registry)
    validation_error = _validate_candidate_url(parsed, allowed_hosts=allowed_hosts)
    if validation_error is not None:
        return _attach_robots_fields(
            out,
            robots_allowed=False,
            robots_reason=validation_error,
            robots_matched_rule=None,
            robots_fetched_status="unreachable",
        )

    cache_key = (scheme, host)
    cached = cache.get(cache_key)
    now = time.time()
    use_fresh_cache = cached is not None and (now - cached.fetched_at) <= cache_max_age_seconds
    if use_fresh_cache:
        stats.robots_cache_hits += 1
        effective = cached
    else:
        stats.robots_cache_misses += 1
        fetched = fetch_robots_txt(
            target_url,
            client,
            limits,
            allowed_hosts=allowed_hosts,
        )
        _count_fetch_status(stats, fetched.status)
        if fetched.status == "unreachable" and cached is not None:
            effective = cached
        else:
            cache[cache_key] = fetched
            effective = fetched

    robots_path = parsed.path or "/"
    if parsed.query:
        robots_path = f"{robots_path}?{parsed.query}"

    if effective.status in ("unavailable", "redirected"):
        return _attach_robots_fields(
            out,
            robots_allowed=True,
            robots_reason="unavailable_allow_all",
            robots_matched_rule=None,
            robots_fetched_status=effective.status,
        )
    if effective.status == "unreachable":
        return _attach_robots_fields(
            out,
            robots_allowed=False,
            robots_reason="unreachable_disallow_all",
            robots_matched_rule=None,
            robots_fetched_status=effective.status,
        )
    if effective.status == "parse_error":
        return _attach_robots_fields(
            out,
            robots_allowed=False,
            robots_reason="parse_error_disallow_all",
            robots_matched_rule=None,
            robots_fetched_status=effective.status,
        )

    allowed, matched_rule = is_allowed(effective.policy, user_agent_token, robots_path)
    if matched_rule is not None:
        reason = "allowed" if allowed else "disallowed"
    else:
        reason = "no_rule_allow" if has_matching_group(effective.policy, user_agent_token) else "no_group_allow"

    return _attach_robots_fields(
        out,
        robots_allowed=allowed,
        robots_reason=reason,
        robots_matched_rule=matched_rule,
        robots_fetched_status=effective.status,
    )


def _extract_candidate_url(candidate: dict[str, Any]) -> str:
    for key in ("official_url", "url"):
        value = candidate.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _resolve_allowed_hosts(candidate: dict[str, Any], registry: Any) -> set[str]:
    brand_key = candidate.get("brand_key")
    if isinstance(brand_key, str) and brand_key.strip():
        domains = get_allowed_domains(registry, brand_key.strip())
        if domains:
            return {d.lower() for d in domains}
    fallback = candidate.get("allowed_domains")
    if isinstance(fallback, list):
        return {str(d).strip().lower() for d in fallback if isinstance(d, str) and d.strip()}
    return set()


def _validate_candidate_url(parsed, *, allowed_hosts: set[str]) -> str | None:
    if parsed.scheme.lower() != "https":
        return "invalid_scheme"
    host = (parsed.hostname or "").lower()
    if not host:
        return "missing_host"
    if host == "localhost" or host.endswith(".localhost"):
        return "localhost_disallowed"
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        ip_obj = None
    if ip_obj is not None:
        if (
            ip_obj.is_private
            or ip_obj.is_reserved
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        ):
            return "private_or_reserved_ip_disallowed"
        return "ip_literal_disallowed"
    if host not in allowed_hosts:
        return "host_not_allowlisted"
    return None


def _attach_robots_fields(
    obj: dict[str, Any],
    *,
    robots_allowed: bool,
    robots_reason: str,
    robots_matched_rule: dict[str, object] | None,
    robots_fetched_status: str,
) -> dict[str, Any]:
    obj["robots_allowed"] = bool(robots_allowed)
    obj["robots_reason"] = robots_reason
    obj["robots_matched_rule"] = robots_matched_rule
    obj["robots_fetched_status"] = robots_fetched_status
    return obj


def _mark_internal_error(candidate: dict[str, Any]) -> dict[str, Any]:
    return _attach_robots_fields(
        dict(candidate),
        robots_allowed=False,
        robots_reason="internal_error",
        robots_matched_rule=None,
        robots_fetched_status="unreachable",
    )


def _count_fetch_status(stats: _GateStats, status: str) -> None:
    if status == "success":
        stats.fetch_success += 1
        return
    if status in ("unavailable", "redirected"):
        stats.fetch_unavailable += 1
        return
    if status == "unreachable":
        stats.fetch_unreachable += 1
        return
    if status == "parse_error":
        stats.fetch_parse_error += 1


def _print_stats(stats: _GateStats) -> None:
    print(f"total_candidates={stats.total_candidates}", file=sys.stderr)
    print(f"allowed={stats.allowed} disallowed={stats.disallowed}", file=sys.stderr)
    print(
        f"robots_cache_hits={stats.robots_cache_hits} robots_cache_misses={stats.robots_cache_misses}",
        file=sys.stderr,
    )
    print(
        "fetch_success={0} fetch_unavailable={1} fetch_unreachable={2} fetch_parse_error={3}".format(
            stats.fetch_success,
            stats.fetch_unavailable,
            stats.fetch_unreachable,
            stats.fetch_parse_error,
        ),
        file=sys.stderr,
    )
    print(f"errors_count={stats.errors_count}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
