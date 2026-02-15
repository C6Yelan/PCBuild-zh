from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

try:
    import httpx
except ModuleNotFoundError:  # pragma: no cover - runtime dependency guard
    httpx = None  # type: ignore[assignment]

from backend.services.crawler.official_reconcile_gate.planning.registry import (
    get_allowed_domains,
    get_sitemap_urls,
)
from backend.services.crawler.official_reconcile_gate.planning.types import OfficialRegistry

from .candidate_filters import is_candidate_allowed_for_plan
from .sitemap import SitemapParseError, decode_sitemap_bytes, parse_sitemap
from .types import DiscoveryEvidence, DiscoveryPlanReport, DiscoveryResult, SitemapCandidate
from .url_normalize import normalize_official_url

_REDIRECT_CODES = {301, 302, 303, 307, 308}
_SITEMAP_ENTRY_PATHS = (
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap-index.xml",
    "/sitemap/sitemap.xml",
)
SITEMAP_FETCH_MAX_BYTES = 2 * 1024 * 1024
_BLOCKED_HTTP_STATUSES = {401, 403, 429}
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+", flags=re.UNICODE)
_LOC_TAG_RE = re.compile(r"<\s*loc\s*>\s*(.*?)\s*<\s*/\s*loc\s*>", flags=re.IGNORECASE | re.DOTALL)


@dataclass(frozen=True)
class _ScoredRow:
    url: str
    score: int
    matched_tokens: list[str]
    discovery_source: str


@dataclass(frozen=True)
class _PlanInput:
    plan_index: int
    retail_url: str
    source: str
    category: str
    brand_key: str | None
    query_terms: list[str]
    allowed_domains: list[str]
    sitemap_urls: list[str]


@dataclass
class _PlanDiscoveryState:
    entrypoints_tried: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    attempted_urls: set[str] = field(default_factory=set)
    fetched_sitemaps: int = 0
    parsed_urlsets: int = 0
    parsed_indexes: int = 0
    candidates_emitted: int = 0
    registry_used: bool = False
    default_used: bool = False
    blocked_http_status: int | None = None


class _SitemapFetchError(RuntimeError):
    def __init__(
        self,
        reason: str,
        detail: str = "",
        request_count: int = 0,
        response_headers: Mapping[str, str] | None = None,
    ) -> None:
        message = reason if not detail else f"{reason}: {detail}"
        super().__init__(message)
        self.reason = reason
        self.detail = detail
        self.request_count = request_count
        self.response_headers = _normalize_headers(response_headers)


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def classify_discovery_error(
    status_code: int | None,
    headers: Mapping[str, str] | None,
) -> tuple[str, str]:
    normalized_headers = _normalize_headers(headers)
    if status_code == 403 and _is_cloudflare_block(headers=normalized_headers):
        return ("blocked", "cloudflare_403")
    if status_code is None:
        return ("http_status", "")
    return ("http_status", str(status_code))


def _normalize_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    if headers is None:
        return {}
    out: dict[str, str] = {}
    for key, value in headers.items():
        key_text = str(key).strip().lower()
        if not key_text:
            continue
        out[key_text] = str(value).strip()
    return out


def _is_cloudflare_block(*, headers: Mapping[str, str]) -> bool:
    server = headers.get("server", "")
    if "cloudflare" in server.lower():
        return True
    for key in headers:
        key_lc = key.lower()
        if key_lc in {"cf-ray", "cf-cache-status"} or key_lc.startswith("cf-"):
            return True
    return False


def discover_candidates_from_plans(
    plans: list[Any],
    *,
    registry: OfficialRegistry,
    max_sitemaps_per_domain: int = 10,
    topk: int = 5,
    min_score: int = 1,
    timeout_seconds: float = 10.0,
    max_bytes: int = 5_242_880,
    max_redirects: int = 5,
) -> DiscoveryResult:
    result = DiscoveryResult()
    if max_sitemaps_per_domain <= 0:
        raise ValueError("max_sitemaps_per_domain must be > 0")
    if topk <= 0:
        raise ValueError("topk must be > 0")
    if min_score < 0:
        raise ValueError("min_score must be >= 0")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be > 0")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be > 0")
    if max_redirects < 0:
        raise ValueError("max_redirects must be >= 0")

    client = _build_fetch_client(timeout_seconds=timeout_seconds)
    try:
        for idx, raw_plan in enumerate(plans):
            result.total_plans += 1
            plan = _normalize_plan(raw_plan, idx=idx, registry=registry)
            if plan is None:
                result.skipped_plans += 1
                _append_skipped_plan_report(result, raw_plan=raw_plan, idx=idx)
                continue

            result.ok_plans += 1
            scored_rows: list[_ScoredRow] = []
            plan_state = _PlanDiscoveryState()
            allowed_hosts = {d.lower() for d in plan.allowed_domains if d}
            registry_entry_urls = _dedupe_urls(plan.sitemap_urls)
            default_entry_urls = _dedupe_urls(_build_default_entry_urls(plan.allowed_domains))

            if registry_entry_urls:
                plan_state.registry_used = True
                result.seeds_used_count += 1
                _try_entrypoints(
                    result=result,
                    plan_state=plan_state,
                    scored_rows=scored_rows,
                    client=client,
                    allowed_hosts=allowed_hosts,
                    entry_urls=registry_entry_urls,
                    source_label="registry",
                    max_sitemaps_per_domain=max_sitemaps_per_domain,
                    query_terms=plan.query_terms,
                    topk=topk,
                    min_score=min_score,
                    timeout_seconds=timeout_seconds,
                    max_bytes=SITEMAP_FETCH_MAX_BYTES,
                    max_redirects=max_redirects,
                )
                if plan_state.blocked_http_status is not None:
                    _append_plan_report(result, plan, plan_state)
                    continue

                should_fallback_to_default = (
                    plan_state.parsed_urlsets == 0
                    and plan_state.parsed_indexes == 0
                    and not scored_rows
                )
                if should_fallback_to_default:
                    fallback_entry_urls = _filter_unattempted_urls(
                        default_entry_urls,
                        attempted=plan_state.attempted_urls,
                    )
                    if fallback_entry_urls:
                        plan_state.default_used = True
                        result.default_entrypoints_used_count += 1
                        _try_entrypoints(
                            result=result,
                            plan_state=plan_state,
                            scored_rows=scored_rows,
                            client=client,
                            allowed_hosts=allowed_hosts,
                            entry_urls=fallback_entry_urls,
                            source_label="default",
                            max_sitemaps_per_domain=max_sitemaps_per_domain,
                            query_terms=plan.query_terms,
                            topk=topk,
                            min_score=min_score,
                            timeout_seconds=timeout_seconds,
                            max_bytes=SITEMAP_FETCH_MAX_BYTES,
                            max_redirects=max_redirects,
                        )
                        if plan_state.blocked_http_status is not None:
                            _append_plan_report(result, plan, plan_state)
                            continue
            else:
                if default_entry_urls:
                    plan_state.default_used = True
                    result.default_entrypoints_used_count += 1
                _try_entrypoints(
                    result=result,
                    plan_state=plan_state,
                    scored_rows=scored_rows,
                    client=client,
                    allowed_hosts=allowed_hosts,
                    entry_urls=default_entry_urls,
                    source_label="default",
                    max_sitemaps_per_domain=max_sitemaps_per_domain,
                    query_terms=plan.query_terms,
                    topk=topk,
                    min_score=min_score,
                    timeout_seconds=timeout_seconds,
                    max_bytes=SITEMAP_FETCH_MAX_BYTES,
                    max_redirects=max_redirects,
                )
                if plan_state.blocked_http_status is not None:
                    _append_plan_report(result, plan, plan_state)
                    continue

            if plan_state.parsed_urlsets == 0 and plan_state.parsed_indexes == 0 and plan_state.blocked_http_status is None:
                robots_entry_urls = _fetch_robots_sitemap_entry_urls(
                    result=result,
                    client=client,
                    plan_state=plan_state,
                    allowed_hosts=allowed_hosts,
                    allowed_domains=plan.allowed_domains,
                    timeout_seconds=timeout_seconds,
                    max_bytes=SITEMAP_FETCH_MAX_BYTES,
                    max_redirects=max_redirects,
                )
                robots_entry_urls = _filter_unattempted_urls(
                    _dedupe_urls(robots_entry_urls),
                    attempted=plan_state.attempted_urls,
                )
                if robots_entry_urls:
                    _try_entrypoints(
                        result=result,
                        plan_state=plan_state,
                        scored_rows=scored_rows,
                        client=client,
                        allowed_hosts=allowed_hosts,
                        entry_urls=robots_entry_urls,
                        source_label="robots",
                        max_sitemaps_per_domain=max_sitemaps_per_domain,
                        query_terms=plan.query_terms,
                        topk=topk,
                        min_score=min_score,
                        timeout_seconds=timeout_seconds,
                        max_bytes=SITEMAP_FETCH_MAX_BYTES,
                        max_redirects=max_redirects,
                    )

            if plan_state.blocked_http_status is not None:
                _append_plan_report(result, plan, plan_state)
                continue

            if plan_state.parsed_urlsets == 0 and plan_state.parsed_indexes == 0:
                result.add_error("no_sitemap_found")
                _append_plan_report(result, plan, plan_state)
                continue

            top_rows = _select_top_rows(scored_rows, topk=topk)
            if not top_rows:
                plan_state.candidates_emitted = 0
                result.plans_no_hits += 1
                _append_plan_report(result, plan, plan_state)
                continue

            emitted_count = 0
            for row in top_rows:
                normalized_official_url = normalize_official_url(row.url)
                if not is_candidate_allowed_for_plan(plan.category, plan.brand_key, normalized_official_url):
                    continue
                evidence = DiscoveryEvidence(
                    discovery_method="sitemap",
                    discovery_source=row.discovery_source,
                    query_terms=list(plan.query_terms),
                    matched_tokens=list(row.matched_tokens),
                    candidate_rank=emitted_count,
                    notes=f"matched_tokens={row.matched_tokens}, score={row.score}",
                )
                result.candidates.append(
                    SitemapCandidate(
                        plan_index=plan.plan_index,
                        retail_url=plan.retail_url,
                        source=plan.source,
                        category=plan.category,
                        brand_key=plan.brand_key,
                        official_url=normalized_official_url,
                        score=row.score,
                        evidence=evidence,
                    )
                )
                emitted_count += 1

            plan_state.candidates_emitted = emitted_count
            if emitted_count == 0:
                result.plans_no_hits += 1
                _append_plan_report(result, plan, plan_state)
                continue

            result.plans_with_hits += 1
            _append_plan_report(result, plan, plan_state)
    finally:
        _close_fetch_client(client)

    result.total_candidates_emitted = len(result.candidates)
    return result


def _build_fetch_client(*, timeout_seconds: float) -> Any:
    if httpx is None:
        return build_opener(_NoRedirectHandler())
    timeout = httpx.Timeout(timeout_seconds, connect=timeout_seconds, read=timeout_seconds)
    return httpx.Client(timeout=timeout, follow_redirects=False)


def _close_fetch_client(client: Any) -> None:
    close_fn = getattr(client, "close", None)
    if callable(close_fn):
        close_fn()


def _build_default_entry_urls(allowed_domains: list[str]) -> list[str]:
    urls: list[str] = []
    for domain in allowed_domains:
        urls.extend(_build_sitemap_entrypoints(domain.lower()))
    return urls


def parse_robots_sitemaps(text: str) -> list[str]:
    if not isinstance(text, str):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() != "sitemap":
            continue
        url = value.strip()
        if not url:
            continue
        lowered = url.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        out.append(url)
    return out


def _filter_unattempted_urls(urls: list[str], *, attempted: set[str]) -> list[str]:
    out: list[str] = []
    for url in urls:
        lowered = url.strip().lower()
        if not lowered or lowered in attempted:
            continue
        out.append(url)
    return out


def _fetch_robots_sitemap_entry_urls(
    *,
    result: DiscoveryResult,
    client: Any,
    plan_state: _PlanDiscoveryState,
    allowed_hosts: set[str],
    allowed_domains: list[str],
    timeout_seconds: float,
    max_bytes: int,
    max_redirects: int,
) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for domain in allowed_domains:
        normalized_domain = domain.strip().lower()
        if not normalized_domain:
            continue
        robots_url = f"https://{normalized_domain}/robots.txt"
        try:
            text, request_count = _fetch_robots_txt(
                client=client,
                robots_url=robots_url,
                allowed_hosts=allowed_hosts,
                timeout_seconds=timeout_seconds,
                max_bytes=max_bytes,
                max_redirects=max_redirects,
            )
            plan_state.fetched_sitemaps += request_count
        except _SitemapFetchError as exc:
            plan_state.fetched_sitemaps += exc.request_count
            mapped_reason, mapped_detail, status_code = _classify_fetch_error(exc)
            result.add_error(mapped_reason)
            _append_fetch_error(
                plan_state,
                source_label="robots",
                url=robots_url,
                reason=mapped_reason,
                detail=mapped_detail,
                status_code=status_code,
            )
            if mapped_reason == "blocked_http_status":
                plan_state.blocked_http_status = status_code
                break
            continue

        sitemap_urls = parse_robots_sitemaps(text)
        plan_state.entrypoints_tried.append(
            {
                "source": "robots",
                "url": robots_url,
                "kind": "robots",
                "status": "ok",
                "sitemap_count": len(sitemap_urls),
            }
        )
        for sitemap_url in sitemap_urls:
            lowered = sitemap_url.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            out.append(sitemap_url)
    return out


def _fetch_robots_txt(
    *,
    client: Any,
    robots_url: str,
    allowed_hosts: set[str],
    timeout_seconds: float,
    max_bytes: int,
    max_redirects: int,
) -> tuple[str, int]:
    current_url = robots_url
    request_count = 0
    range_header_value = f"bytes=0-{max_bytes - 1}"

    if httpx is None:
        opener = client
        for _ in range(max_redirects + 1):
            validation_error = _validate_robots_url(current_url, allowed_hosts)
            if validation_error is not None:
                raise _SitemapFetchError(validation_error, current_url, request_count=request_count)

            request = Request(current_url, method="GET", headers={"Range": range_header_value})
            try:
                with opener.open(request, timeout=timeout_seconds) as response:
                    request_count += 1
                    status_code = getattr(response, "status", response.getcode())
                    if status_code in _REDIRECT_CODES:
                        location = response.headers.get("Location")
                        if not location:
                            raise _SitemapFetchError(
                                "redirect_without_location",
                                current_url,
                                request_count=request_count,
                            )
                        current_url = urljoin(current_url, location)
                        continue
                    if status_code != 200:
                        raise _SitemapFetchError(
                            "http_status",
                            str(status_code),
                            request_count=request_count,
                            response_headers=response.headers,
                        )
                    payload, _ = _read_urllib_response_bytes(response, max_bytes=max_bytes)
                    return payload.decode("utf-8", errors="ignore"), request_count
            except HTTPError as exc:
                request_count += 1
                if exc.code in _REDIRECT_CODES:
                    location = exc.headers.get("Location", "") if exc.headers else ""
                    if not location:
                        raise _SitemapFetchError(
                            "redirect_without_location",
                            current_url,
                            request_count=request_count,
                        ) from exc
                    current_url = urljoin(current_url, location)
                    continue
                raise _SitemapFetchError(
                    "http_status",
                    str(exc.code),
                    request_count=request_count,
                    response_headers=exc.headers,
                ) from exc
            except socket.timeout as exc:
                raise _SitemapFetchError("timeout", str(exc), request_count=request_count) from exc
            except TimeoutError as exc:
                raise _SitemapFetchError("timeout", str(exc), request_count=request_count) from exc
            except URLError as exc:
                raise _SitemapFetchError("request_error", str(exc.reason), request_count=request_count) from exc
        raise _SitemapFetchError("too_many_redirects", robots_url, request_count=request_count)

    for _ in range(max_redirects + 1):
        validation_error = _validate_robots_url(current_url, allowed_hosts)
        if validation_error is not None:
            raise _SitemapFetchError(validation_error, current_url, request_count=request_count)

        try:
            with client.stream("GET", current_url, headers={"Range": range_header_value}) as response:
                request_count += 1
                if response.status_code in _REDIRECT_CODES:
                    location = response.headers.get("location")
                    if not location:
                        raise _SitemapFetchError(
                            "redirect_without_location",
                            current_url,
                            request_count=request_count,
                        )
                    current_url = urljoin(current_url, location)
                    continue
                if response.status_code != 200:
                    raise _SitemapFetchError(
                        "http_status",
                        str(response.status_code),
                        request_count=request_count,
                        response_headers=response.headers,
                    )
                payload, _ = _read_response_bytes(response, max_bytes=max_bytes)
                return payload.decode("utf-8", errors="ignore"), request_count
        except httpx.TimeoutException as exc:
            raise _SitemapFetchError("timeout", str(exc), request_count=request_count) from exc
        except httpx.RequestError as exc:
            raise _SitemapFetchError("request_error", str(exc), request_count=request_count) from exc
    raise _SitemapFetchError("too_many_redirects", robots_url, request_count=request_count)


def _try_entrypoints(
    *,
    result: DiscoveryResult,
    plan_state: _PlanDiscoveryState,
    scored_rows: list[_ScoredRow],
    client: Any,
    allowed_hosts: set[str],
    entry_urls: list[str],
    source_label: str,
    max_sitemaps_per_domain: int,
    query_terms: list[str],
    topk: int,
    min_score: int,
    timeout_seconds: float,
    max_bytes: int,
    max_redirects: int,
) -> None:
    for entry_url in entry_urls:
        if plan_state.blocked_http_status is not None:
            return
        normalized = entry_url.strip().lower()
        if not normalized:
            continue
        if normalized in plan_state.attempted_urls:
            continue
        plan_state.attempted_urls.add(normalized)

        try:
            entry_kind, entry_values, request_count = _fetch_and_parse_sitemap(
                client=client,
                sitemap_url=entry_url,
                allowed_hosts=allowed_hosts,
                timeout_seconds=timeout_seconds,
                max_bytes=max_bytes,
                max_redirects=max_redirects,
            )
            result.fetched_sitemaps += request_count
            plan_state.fetched_sitemaps += request_count
        except _SitemapFetchError as exc:
            result.fetched_sitemaps += exc.request_count
            plan_state.fetched_sitemaps += exc.request_count
            mapped_reason, mapped_detail, status_code = _classify_fetch_error(exc)
            result.add_error(mapped_reason)
            _append_fetch_error(
                plan_state,
                source_label=source_label,
                url=entry_url,
                reason=mapped_reason,
                detail=mapped_detail,
                status_code=status_code,
            )
            if mapped_reason == "blocked_http_status":
                plan_state.blocked_http_status = status_code
                return
            continue
        except SitemapParseError as exc:
            mapped_reason = _map_parse_error_reason(exc)
            result.add_error(mapped_reason)
            _append_parse_error(plan_state, source_label=source_label, url=entry_url, exc=exc, mapped_reason=mapped_reason)
            continue

        if entry_kind == "urlset":
            plan_state.parsed_urlsets += 1
            result.parsed_urlsets += 1
            plan_state.entrypoints_tried.append(
                {
                    "source": source_label,
                    "url": entry_url,
                    "kind": "urlset",
                    "status": "ok",
                }
            )
            _append_scored_rows(
                scored_rows,
                urls=entry_values,
                query_terms=query_terms,
                discovery_source=entry_url,
                topk=topk,
                min_score=min_score,
            )
            break

        plan_state.parsed_indexes += 1
        result.parsed_indexes += 1
        plan_state.entrypoints_tried.append(
            {
                "source": source_label,
                "url": entry_url,
                "kind": "index",
                "status": "ok",
                "child_count": len(entry_values),
            }
        )
        child_urls = entry_values[:max_sitemaps_per_domain]
        for child_sitemap_url in child_urls:
            child_norm = child_sitemap_url.strip().lower()
            if not child_norm:
                continue
            if child_norm in plan_state.attempted_urls:
                continue
            plan_state.attempted_urls.add(child_norm)
            try:
                child_kind, child_values, child_request_count = _fetch_and_parse_sitemap(
                    client=client,
                    sitemap_url=child_sitemap_url,
                    allowed_hosts=allowed_hosts,
                    timeout_seconds=timeout_seconds,
                    max_bytes=max_bytes,
                    max_redirects=max_redirects,
                )
                result.fetched_sitemaps += child_request_count
                plan_state.fetched_sitemaps += child_request_count
            except _SitemapFetchError as exc:
                result.fetched_sitemaps += exc.request_count
                plan_state.fetched_sitemaps += exc.request_count
                mapped_reason, mapped_detail, status_code = _classify_fetch_error(exc)
                result.add_error(mapped_reason)
                _append_fetch_error(
                    plan_state,
                    source_label=source_label,
                    url=child_sitemap_url,
                    reason=mapped_reason,
                    detail=mapped_detail,
                    status_code=status_code,
                )
                if mapped_reason == "blocked_http_status":
                    plan_state.blocked_http_status = status_code
                    return
                continue
            except SitemapParseError as exc:
                mapped_reason = _map_parse_error_reason(exc)
                result.add_error(mapped_reason)
                _append_parse_error(
                    plan_state,
                    source_label=source_label,
                    url=child_sitemap_url,
                    exc=exc,
                    mapped_reason=mapped_reason,
                )
                continue

            if child_kind == "urlset":
                plan_state.parsed_urlsets += 1
                result.parsed_urlsets += 1
                plan_state.entrypoints_tried.append(
                    {
                        "source": source_label,
                        "url": child_sitemap_url,
                        "kind": "urlset",
                        "status": "ok",
                        "via": entry_url,
                    }
                )
                _append_scored_rows(
                    scored_rows,
                    urls=child_values,
                    query_terms=query_terms,
                    discovery_source=child_sitemap_url,
                    topk=topk,
                    min_score=min_score,
                )
                continue

            plan_state.parsed_indexes += 1
            result.parsed_indexes += 1
            result.add_error("nested_index_ignored")
            plan_state.entrypoints_tried.append(
                {
                    "source": source_label,
                    "url": child_sitemap_url,
                    "kind": "index",
                    "status": "nested_index_ignored",
                    "via": entry_url,
                }
            )
            plan_state.errors.append(
                {
                    "reason": "nested_index_ignored",
                    "url": child_sitemap_url,
                    "source": source_label,
                }
            )
        break


def _classify_fetch_error(exc: _SitemapFetchError) -> tuple[str, str, int | None]:
    status_code: int | None = None
    if exc.reason == "http_status":
        try:
            status_code = int(exc.detail)
        except ValueError:
            status_code = None
        if status_code in _BLOCKED_HTTP_STATUSES:
            return ("blocked_http_status", str(status_code), status_code)
        reason, detail = classify_discovery_error(status_code, exc.response_headers)
        if reason == "http_status":
            return (reason, exc.detail, status_code)
        return (reason, detail, status_code)
    return (exc.reason, exc.detail, status_code)


def _append_fetch_error(
    plan_state: _PlanDiscoveryState,
    *,
    source_label: str,
    url: str,
    reason: str,
    detail: str,
    status_code: int | None,
) -> None:
    attempt = {
        "source": source_label,
        "url": url,
        "kind": "entrypoint",
        "status": "error",
        "reason": reason,
    }
    if status_code is not None:
        attempt["status_code"] = status_code
    if detail:
        attempt["detail"] = detail
    plan_state.entrypoints_tried.append(attempt)

    error_obj = {
        "reason": reason,
        "url": url,
        "source": source_label,
    }
    if status_code is not None:
        error_obj["status_code"] = status_code
    if detail:
        error_obj["detail"] = detail
    plan_state.errors.append(error_obj)


def _append_parse_error(
    plan_state: _PlanDiscoveryState,
    *,
    source_label: str,
    url: str,
    exc: SitemapParseError,
    mapped_reason: str,
) -> None:
    plan_state.entrypoints_tried.append(
        {
            "source": source_label,
            "url": url,
            "kind": "entrypoint",
            "status": "error",
            "reason": mapped_reason,
            "detail": exc.detail,
        }
    )
    plan_state.errors.append(
        {
            "reason": mapped_reason,
            "url": url,
            "source": source_label,
            "detail": exc.detail,
        }
    )


def _append_plan_report(result: DiscoveryResult, plan: _PlanInput, plan_state: _PlanDiscoveryState) -> None:
    decision = "quarantine" if plan_state.blocked_http_status is not None else "ok"
    result.plan_reports.append(
        DiscoveryPlanReport(
            plan_index=plan.plan_index,
            brand_key=plan.brand_key,
            category=plan.category,
            decision=decision,
            allowed_domains=list(plan.allowed_domains),
            registry_used=plan_state.registry_used,
            default_used=plan_state.default_used,
            entrypoints_tried=list(plan_state.entrypoints_tried),
            fetched_sitemaps=plan_state.fetched_sitemaps,
            parsed_urlsets=plan_state.parsed_urlsets,
            parsed_indexes=plan_state.parsed_indexes,
            candidates_emitted=plan_state.candidates_emitted,
            errors=list(plan_state.errors),
        )
    )


def _append_skipped_plan_report(result: DiscoveryResult, *, raw_plan: Any, idx: int) -> None:
    if isinstance(raw_plan, dict):
        decision_value = raw_plan.get("decision")
        decision = decision_value.strip() if isinstance(decision_value, str) and decision_value.strip() else None
        brand_key_value = raw_plan.get("brand_key")
        brand_key = brand_key_value.strip() if isinstance(brand_key_value, str) and brand_key_value.strip() else None
        category_value = raw_plan.get("category")
        category = category_value.strip() if isinstance(category_value, str) else ""
        allowed_raw = raw_plan.get("allowed_domains")
        if isinstance(allowed_raw, list):
            allowed_domains = [str(item).strip() for item in allowed_raw if isinstance(item, str) and item.strip()]
        else:
            allowed_domains = []
        errors = [{"reason": "plan_skipped", "detail": decision or "invalid_plan"}]
    else:
        decision = None
        brand_key = None
        category = ""
        allowed_domains = []
        errors = [{"reason": "plan_skipped", "detail": "invalid_plan"}]

    result.plan_reports.append(
        DiscoveryPlanReport(
            plan_index=idx,
            brand_key=brand_key,
            category=category,
            decision=decision,
            allowed_domains=allowed_domains,
            registry_used=False,
            default_used=False,
            entrypoints_tried=[],
            fetched_sitemaps=0,
            parsed_urlsets=0,
            parsed_indexes=0,
            candidates_emitted=0,
            errors=errors,
        )
    )


def _dedupe_urls(urls: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for url in urls:
        normalized = url.strip()
        if not normalized:
            continue
        lowered = normalized.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        out.append(normalized)
    return out


def _tokenize_query_terms(query_terms: list[str]) -> list[str]:
    tokens: list[str] = []
    seen: set[str] = set()
    for value in query_terms:
        if not isinstance(value, str):
            continue
        for raw_token in _TOKEN_SPLIT_RE.split(value.lower()):
            token = raw_token.strip()
            if not token:
                continue
            if token.isdigit():
                if len(token) < 3:
                    continue
            elif len(token) < 3:
                continue
            if token in seen:
                continue
            seen.add(token)
            tokens.append(token)
    return tokens


def score_candidate_urls(
    urls: list[str],
    query_terms: list[str],
    *,
    topk: int = 5,
    min_score: int = 1,
) -> list[tuple[str, int, list[str]]]:
    if min_score < 0:
        raise ValueError("min_score must be >= 0")
    normalized_tokens = _tokenize_query_terms(query_terms)
    dedup: dict[str, str] = {}
    for raw_url in urls:
        if not isinstance(raw_url, str):
            continue
        trimmed = raw_url.strip()
        if not trimmed:
            continue
        dedup.setdefault(trimmed.lower(), trimmed)

    scored: list[tuple[str, int, list[str]]] = []
    for normalized_url, original_url in dedup.items():
        matched_tokens = [token for token in normalized_tokens if token in normalized_url]
        score = len(matched_tokens)
        if score >= min_score:
            scored.append((original_url, score, matched_tokens))

    scored.sort(key=lambda row: (-row[1], row[0].lower(), row[0]))
    if topk <= 0:
        return []
    return scored[:topk]


def _append_scored_rows(
    rows: list[_ScoredRow],
    *,
    urls: list[str],
    query_terms: list[str],
    discovery_source: str,
    topk: int,
    min_score: int,
) -> None:
    for url, score, matched_tokens in score_candidate_urls(
        urls,
        query_terms,
        topk=topk,
        min_score=min_score,
    ):
        rows.append(
            _ScoredRow(
                url=url,
                score=score,
                matched_tokens=matched_tokens,
                discovery_source=discovery_source,
            )
        )


def _select_top_rows(rows: list[_ScoredRow], *, topk: int) -> list[_ScoredRow]:
    rows.sort(key=lambda row: (-row.score, row.url.lower(), row.discovery_source.lower(), row.url))
    deduped: list[_ScoredRow] = []
    seen_urls: set[str] = set()
    for row in rows:
        key = row.url.lower()
        if key in seen_urls:
            continue
        seen_urls.add(key)
        deduped.append(row)
        if len(deduped) >= topk:
            break
    return deduped


def _fetch_and_parse_sitemap(
    *,
    client: Any,
    sitemap_url: str,
    allowed_hosts: set[str],
    timeout_seconds: float,
    max_bytes: int,
    max_redirects: int,
) -> tuple[str, list[str], int]:
    max_bytes = SITEMAP_FETCH_MAX_BYTES
    final_url, payload, content_type, content_encoding, request_count, truncated = _fetch_sitemap_bytes(
        client=client,
        sitemap_url=sitemap_url,
        allowed_hosts=allowed_hosts,
        timeout_seconds=timeout_seconds,
        max_bytes=max_bytes,
        max_redirects=max_redirects,
    )
    decoded: bytes
    try:
        decoded = decode_sitemap_bytes(
            payload,
            url=final_url,
            content_type=content_type,
            content_encoding=content_encoding,
        )
    except SitemapParseError:
        if not truncated:
            raise
        decoded = bytes(payload)

    if not truncated:
        kind, values = parse_sitemap(decoded)
        return kind, values, request_count

    kind, values = _extract_loc_urls_from_truncated_sitemap(decoded)
    if values:
        return kind, values, request_count
    raise _SitemapFetchError("too_large", str(max_bytes), request_count=request_count)


def _fetch_sitemap_bytes(
    *,
    client: Any,
    sitemap_url: str,
    allowed_hosts: set[str],
    timeout_seconds: float,
    max_bytes: int,
    max_redirects: int,
) -> tuple[str, bytes, str, str, int, bool]:
    current_url = sitemap_url
    request_count = 0

    if httpx is None:
        return _fetch_sitemap_bytes_stdlib(
            client=client,
            sitemap_url=sitemap_url,
            allowed_hosts=allowed_hosts,
            timeout_seconds=timeout_seconds,
            max_bytes=max_bytes,
            max_redirects=max_redirects,
        )

    range_header_value = f"bytes=0-{max_bytes - 1}"

    for _ in range(max_redirects + 1):
        validation_error = _validate_sitemap_url(current_url, allowed_hosts)
        if validation_error is not None:
            raise _SitemapFetchError(validation_error, current_url, request_count=request_count)

        try:
            with client.stream("GET", current_url, headers={"Range": range_header_value}) as response:
                request_count += 1
                if response.status_code in _REDIRECT_CODES:
                    location = response.headers.get("location")
                    if not location:
                        raise _SitemapFetchError(
                            "redirect_without_location",
                            current_url,
                            request_count=request_count,
                        )
                    current_url = urljoin(current_url, location)
                    continue
                if response.status_code not in {200, 206}:
                    raise _SitemapFetchError(
                        "http_status",
                        str(response.status_code),
                        request_count=request_count,
                        response_headers=response.headers,
                    )
                payload, truncated = _read_response_bytes(response, max_bytes=max_bytes)
                return (
                    current_url,
                    payload,
                    response.headers.get("content-type", ""),
                    response.headers.get("content-encoding", ""),
                    request_count,
                    truncated,
                )
        except httpx.TimeoutException as exc:
            raise _SitemapFetchError("timeout", str(exc), request_count=request_count) from exc
        except httpx.RequestError as exc:
            raise _SitemapFetchError("request_error", str(exc), request_count=request_count) from exc

    raise _SitemapFetchError("too_many_redirects", sitemap_url, request_count=request_count)


def _fetch_sitemap_bytes_stdlib(
    *,
    client: Any,
    sitemap_url: str,
    allowed_hosts: set[str],
    timeout_seconds: float,
    max_bytes: int,
    max_redirects: int,
) -> tuple[str, bytes, str, str, int, bool]:
    current_url = sitemap_url
    request_count = 0
    opener = client
    range_header_value = f"bytes=0-{max_bytes - 1}"

    for _ in range(max_redirects + 1):
        validation_error = _validate_sitemap_url(current_url, allowed_hosts)
        if validation_error is not None:
            raise _SitemapFetchError(validation_error, current_url, request_count=request_count)

        request = Request(current_url, method="GET", headers={"Range": range_header_value})
        try:
            with opener.open(request, timeout=timeout_seconds) as response:
                request_count += 1
                status_code = getattr(response, "status", response.getcode())
                if status_code in _REDIRECT_CODES:
                    location = response.headers.get("Location")
                    if not location:
                        raise _SitemapFetchError(
                            "redirect_without_location",
                            current_url,
                            request_count=request_count,
                        )
                    current_url = urljoin(current_url, location)
                    continue
                if status_code not in {200, 206}:
                    raise _SitemapFetchError(
                        "http_status",
                        str(status_code),
                        request_count=request_count,
                        response_headers=response.headers,
                    )
                payload, truncated = _read_urllib_response_bytes(
                    response,
                    max_bytes=max_bytes,
                )
                return (
                    current_url,
                    payload,
                    response.headers.get("Content-Type", ""),
                    response.headers.get("Content-Encoding", ""),
                    request_count,
                    truncated,
                )
        except HTTPError as exc:
            request_count += 1
            if exc.code in _REDIRECT_CODES:
                location = exc.headers.get("Location", "") if exc.headers else ""
                if not location:
                    raise _SitemapFetchError(
                        "redirect_without_location",
                        current_url,
                        request_count=request_count,
                    ) from exc
                current_url = urljoin(current_url, location)
                continue
            raise _SitemapFetchError(
                "http_status",
                str(exc.code),
                request_count=request_count,
                response_headers=exc.headers,
            ) from exc
        except socket.timeout as exc:
            raise _SitemapFetchError("timeout", str(exc), request_count=request_count) from exc
        except TimeoutError as exc:
            raise _SitemapFetchError("timeout", str(exc), request_count=request_count) from exc
        except URLError as exc:
            raise _SitemapFetchError("request_error", str(exc.reason), request_count=request_count) from exc

    raise _SitemapFetchError("too_many_redirects", sitemap_url, request_count=request_count)


def _read_response_bytes(response: httpx.Response, *, max_bytes: int) -> tuple[bytes, bool]:
    out = bytearray()
    truncated = False
    for chunk in response.iter_bytes():
        if not chunk:
            continue
        remaining = max_bytes - len(out)
        if remaining <= 0:
            truncated = True
            break
        if len(chunk) <= remaining:
            out.extend(chunk)
            continue
        out.extend(chunk[:remaining])
        truncated = True
        break
    return bytes(out), truncated


def _read_urllib_response_bytes(response: Any, *, max_bytes: int) -> tuple[bytes, bool]:
    out = bytearray()
    truncated = False
    while True:
        chunk = response.read(65536)
        if not chunk:
            break
        remaining = max_bytes - len(out)
        if remaining <= 0:
            truncated = True
            break
        if len(chunk) <= remaining:
            out.extend(chunk)
            continue
        out.extend(chunk[:remaining])
        truncated = True
        break
    return bytes(out), truncated


def _extract_loc_urls_from_truncated_sitemap(payload: bytes) -> tuple[str, list[str]]:
    text = payload.decode("utf-8", errors="ignore")
    kind = "index" if "<sitemapindex" in text.lower() else "urlset"
    urls: list[str] = []
    seen: set[str] = set()
    for match in _LOC_TAG_RE.findall(text):
        candidate = (match or "").strip()
        if not candidate:
            continue
        key = candidate.lower()
        if key in seen:
            continue
        seen.add(key)
        urls.append(candidate)
    return kind, urls


def _validate_robots_url(url: str, allowed_hosts: set[str]) -> str | None:
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https":
        return "invalid_scheme"

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return "missing_host"
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return "localhost_disallowed"

    try:
        parsed_ip = ipaddress.ip_address(hostname)
    except ValueError:
        parsed_ip = None

    if parsed_ip is not None:
        if (
            parsed_ip.is_private
            or parsed_ip.is_loopback
            or parsed_ip.is_link_local
            or parsed_ip.is_multicast
            or parsed_ip.is_unspecified
        ):
            return "private_ip_disallowed"
        return "ip_literal_disallowed"

    if hostname not in allowed_hosts:
        return "host_not_allowlisted"

    path = parsed.path or "/"
    if not path.lower().endswith("/robots.txt"):
        return "invalid_robots_path"
    return None


def _validate_sitemap_url(url: str, allowed_hosts: set[str]) -> str | None:
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https":
        return "invalid_scheme"

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return "missing_host"
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return "localhost_disallowed"

    try:
        parsed_ip = ipaddress.ip_address(hostname)
    except ValueError:
        parsed_ip = None

    if parsed_ip is not None:
        if (
            parsed_ip.is_private
            or parsed_ip.is_loopback
            or parsed_ip.is_link_local
            or parsed_ip.is_multicast
            or parsed_ip.is_unspecified
        ):
            return "private_ip_disallowed"
        return "ip_literal_disallowed"

    if hostname not in allowed_hosts:
        return "host_not_allowlisted"

    path = parsed.path or "/"
    path_lower = path.lower()
    if not (path_lower.endswith(".xml") or path_lower.endswith(".xml.gz")):
        return "invalid_sitemap_path"
    return None


def _build_sitemap_entrypoints(domain: str) -> list[str]:
    return [f"https://{domain}{path}" for path in _SITEMAP_ENTRY_PATHS]


def _normalize_plan(raw_plan: Any, *, idx: int, registry: OfficialRegistry) -> _PlanInput | None:
    if not isinstance(raw_plan, dict):
        return None

    decision = _normalize_string(raw_plan.get("decision"))
    if decision != "ok":
        return None

    retail_url = _normalize_string(raw_plan.get("retail_url") or raw_plan.get("url"))
    source = _normalize_string(raw_plan.get("source"))
    category = _normalize_string(raw_plan.get("category"))
    if not retail_url or not source or not category:
        return None

    brand_key = _normalize_string(raw_plan.get("brand_key")) or None
    raw_query_terms = raw_plan.get("query_terms")
    query_terms = _normalize_string_list(raw_query_terms)
    registry_domains = get_allowed_domains(registry, brand_key)
    allowed_domains = _normalize_string_list(registry_domains if registry_domains else raw_plan.get("allowed_domains"))
    registry_sitemap_urls = get_sitemap_urls(registry, brand_key)
    sitemap_urls = _normalize_string_list(
        registry_sitemap_urls if registry_sitemap_urls else raw_plan.get("sitemap_urls")
    )

    return _PlanInput(
        plan_index=idx,
        retail_url=retail_url,
        source=source,
        category=category,
        brand_key=brand_key,
        query_terms=query_terms,
        allowed_domains=allowed_domains,
        sitemap_urls=sitemap_urls,
    )


def _normalize_string(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def _normalize_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for row in value:
        if not isinstance(row, str):
            continue
        item = row.strip()
        if not item:
            continue
        lowered = item.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        out.append(item)
    return out


def _map_parse_error_reason(exc: SitemapParseError) -> str:
    if exc.reason in {"invalid_xml", "invalid_gzip", "invalid_payload_type"}:
        return "invalid_xml"
    return exc.reason
