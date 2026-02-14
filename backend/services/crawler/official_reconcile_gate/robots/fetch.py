from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

try:
    import httpx
except ModuleNotFoundError:  # pragma: no cover - runtime dependency guard
    httpx = None  # type: ignore[assignment]

from .parser import parse_robots_txt
from .types import RobotsFetchResult, RobotsPolicy

_REDIRECT_CODES = {301, 302, 303, 307, 308}


@dataclass(frozen=True)
class RobotsFetchLimits:
    timeout_seconds: float = 10.0
    max_bytes: int = 512_000
    max_redirects: int = 5


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def fetch_robots_txt(
    target: str,
    http_client: Any,
    limits: RobotsFetchLimits,
    *,
    allowed_hosts: set[str] | None = None,
) -> RobotsFetchResult:
    now = time.time()
    host = _extract_host(target)
    if not host:
        return RobotsFetchResult(
            status="unreachable",
            policy=RobotsPolicy.disallow_all("invalid_host"),
            robots_url=str(target),
            error="invalid_host",
            fetched_at=now,
        )

    robots_url = f"https://{host}/robots.txt"

    validation_error = _validate_request_url(robots_url, allowed_hosts=allowed_hosts)
    if validation_error is not None:
        return RobotsFetchResult(
            status="unreachable",
            policy=RobotsPolicy.disallow_all(validation_error),
            robots_url=robots_url,
            error=validation_error,
            fetched_at=now,
        )

    if hasattr(http_client, "stream"):
        return _fetch_with_httpx(
            robots_url,
            client=http_client,
            limits=limits,
            allowed_hosts=allowed_hosts,
        )
    return _fetch_with_urllib(
        robots_url,
        opener=http_client,
        limits=limits,
        allowed_hosts=allowed_hosts,
    )


def build_robots_http_client(limits: RobotsFetchLimits) -> Any:
    if httpx is None:
        return build_opener(_NoRedirectHandler())
    timeout = httpx.Timeout(
        limits.timeout_seconds,
        connect=limits.timeout_seconds,
        read=limits.timeout_seconds,
    )
    return httpx.Client(timeout=timeout, follow_redirects=False)


def close_robots_http_client(client: Any) -> None:
    close_fn = getattr(client, "close", None)
    if callable(close_fn):
        close_fn()


def _fetch_with_httpx(
    robots_url: str,
    *,
    client: Any,
    limits: RobotsFetchLimits,
    allowed_hosts: set[str] | None,
) -> RobotsFetchResult:
    current_url = robots_url
    request_count = 0
    now = time.time()

    for _ in range(limits.max_redirects + 1):
        validation_error = _validate_request_url(current_url, allowed_hosts=allowed_hosts)
        if validation_error is not None:
            return RobotsFetchResult(
                status="unreachable",
                policy=RobotsPolicy.disallow_all(validation_error),
                robots_url=robots_url,
                final_url=current_url,
                error=validation_error,
                fetched_at=now,
            )

        try:
            with client.stream("GET", current_url) as response:
                request_count += 1
                status_code = int(response.status_code)
                if status_code in _REDIRECT_CODES:
                    location = response.headers.get("location", "")
                    if not location:
                        return _unreachable_result(
                            robots_url=robots_url,
                            final_url=current_url,
                            error="redirect_without_location",
                        )
                    current_url = urljoin(current_url, location)
                    continue

                return _build_result_from_http_response(
                    robots_url=robots_url,
                    final_url=current_url,
                    status_code=status_code,
                    payload=_read_httpx_bytes(response, max_bytes=limits.max_bytes),
                )
        except _TooLargeError:
            return _unreachable_result(
                robots_url=robots_url,
                final_url=current_url,
                error="too_large",
            )
        except httpx.TimeoutException as exc:
            return _unreachable_result(
                robots_url=robots_url,
                final_url=current_url,
                error=f"timeout:{exc}",
            )
        except httpx.RequestError as exc:
            return _unreachable_result(
                robots_url=robots_url,
                final_url=current_url,
                error=f"request_error:{exc}",
            )

    return RobotsFetchResult(
        status="unavailable",
        policy=RobotsPolicy.allow_all("redirect_limit_exceeded"),
        robots_url=robots_url,
        final_url=current_url,
        error=f"redirects>{limits.max_redirects}",
        fetched_at=time.time(),
    )


def _fetch_with_urllib(
    robots_url: str,
    *,
    opener: Any,
    limits: RobotsFetchLimits,
    allowed_hosts: set[str] | None,
) -> RobotsFetchResult:
    current_url = robots_url
    now = time.time()

    for _ in range(limits.max_redirects + 1):
        validation_error = _validate_request_url(current_url, allowed_hosts=allowed_hosts)
        if validation_error is not None:
            return RobotsFetchResult(
                status="unreachable",
                policy=RobotsPolicy.disallow_all(validation_error),
                robots_url=robots_url,
                final_url=current_url,
                error=validation_error,
                fetched_at=now,
            )

        request = Request(current_url, method="GET")
        try:
            with opener.open(request, timeout=limits.timeout_seconds) as response:
                status_code = int(getattr(response, "status", response.getcode()))
                if status_code in _REDIRECT_CODES:
                    location = response.headers.get("Location", "")
                    if not location:
                        return _unreachable_result(
                            robots_url=robots_url,
                            final_url=current_url,
                            error="redirect_without_location",
                        )
                    current_url = urljoin(current_url, location)
                    continue

                payload = _read_urllib_bytes(response, max_bytes=limits.max_bytes)
                return _build_result_from_http_response(
                    robots_url=robots_url,
                    final_url=current_url,
                    status_code=status_code,
                    payload=payload,
                )
        except HTTPError as exc:
            if exc.code in _REDIRECT_CODES:
                location = exc.headers.get("Location", "") if exc.headers else ""
                if not location:
                    return _unreachable_result(
                        robots_url=robots_url,
                        final_url=current_url,
                        error="redirect_without_location",
                    )
                current_url = urljoin(current_url, location)
                continue
            return _build_result_from_http_response(
                robots_url=robots_url,
                final_url=current_url,
                status_code=int(exc.code),
                payload=b"",
            )
        except _TooLargeError:
            return _unreachable_result(
                robots_url=robots_url,
                final_url=current_url,
                error="too_large",
            )
        except (socket.timeout, TimeoutError) as exc:
            return _unreachable_result(
                robots_url=robots_url,
                final_url=current_url,
                error=f"timeout:{exc}",
            )
        except URLError as exc:
            return _unreachable_result(
                robots_url=robots_url,
                final_url=current_url,
                error=f"request_error:{exc.reason}",
            )

    return RobotsFetchResult(
        status="unavailable",
        policy=RobotsPolicy.allow_all("redirect_limit_exceeded"),
        robots_url=robots_url,
        final_url=current_url,
        error=f"redirects>{limits.max_redirects}",
        fetched_at=time.time(),
    )


def _build_result_from_http_response(
    *,
    robots_url: str,
    final_url: str,
    status_code: int,
    payload: bytes,
) -> RobotsFetchResult:
    now = time.time()
    if 200 <= status_code < 300:
        try:
            text = payload.decode("utf-8", "ignore")
            policy = parse_robots_txt(text)
        except Exception as exc:
            return RobotsFetchResult(
                status="parse_error",
                policy=RobotsPolicy.disallow_all("parse_error"),
                robots_url=robots_url,
                final_url=final_url,
                http_status=status_code,
                error=str(exc),
                fetched_at=now,
            )
        return RobotsFetchResult(
            status="success",
            policy=policy,
            robots_url=robots_url,
            final_url=final_url,
            http_status=status_code,
            fetched_at=now,
        )
    if 400 <= status_code < 500:
        return RobotsFetchResult(
            status="unavailable",
            policy=RobotsPolicy.allow_all("unavailable_4xx"),
            robots_url=robots_url,
            final_url=final_url,
            http_status=status_code,
            fetched_at=now,
        )
    return RobotsFetchResult(
        status="unreachable",
        policy=RobotsPolicy.disallow_all("unreachable_5xx_or_other"),
        robots_url=robots_url,
        final_url=final_url,
        http_status=status_code,
        fetched_at=now,
    )


def _read_httpx_bytes(response: Any, *, max_bytes: int) -> bytes:
    out = bytearray()
    for chunk in response.iter_bytes():
        out.extend(chunk)
        if len(out) > max_bytes:
            raise _TooLargeError()
    return bytes(out)


def _read_urllib_bytes(response: Any, *, max_bytes: int) -> bytes:
    out = bytearray()
    while True:
        chunk = response.read(65536)
        if not chunk:
            break
        out.extend(chunk)
        if len(out) > max_bytes:
            raise _TooLargeError()
    return bytes(out)


def _extract_host(target: str) -> str:
    text = (target or "").strip()
    if not text:
        return ""
    parsed = urlsplit(text)
    if parsed.scheme:
        return (parsed.hostname or "").lower()
    return text.lower()


def _validate_request_url(url: str, *, allowed_hosts: set[str] | None) -> str | None:
    parsed = urlsplit(url)
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

    if not _host_allowlisted(host, allowed_hosts):
        return "host_not_allowlisted"
    return None


def _host_allowlisted(host: str, allowed_hosts: set[str] | None) -> bool:
    if allowed_hosts is None:
        return True
    if host in allowed_hosts:
        return True
    if host.startswith("www.") and host[4:] in allowed_hosts:
        return True
    if ("www." + host) in allowed_hosts:
        return True
    return False


def _unreachable_result(*, robots_url: str, final_url: str | None, error: str) -> RobotsFetchResult:
    return RobotsFetchResult(
        status="unreachable",
        policy=RobotsPolicy.disallow_all("unreachable"),
        robots_url=robots_url,
        final_url=final_url,
        error=error,
        fetched_at=time.time(),
    )


class _TooLargeError(RuntimeError):
    pass
