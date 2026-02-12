# backend/services/crawler/official_reconcile_gate/fetch.py
"""Generic fetch helper for T6 official reconciliation adapters."""

from __future__ import annotations

import atexit
import ipaddress
import socket
import threading
import time
from dataclasses import dataclass
from urllib.parse import ParseResult, urljoin, urlparse

import httpx

from ..config import CrawlerSettings
from ..robots import RobotsManager

_SETTINGS = CrawlerSettings()
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_HOST_MAX_CONCURRENCY = 1


class FetchTextError(RuntimeError):
    """Base error with stable type key for upper-layer handling."""

    def __init__(
        self,
        error_type: str,
        message: str,
        *,
        url: str,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.url = url
        self.status_code = status_code


class InvalidUrlError(FetchTextError):
    def __init__(self, message: str, *, url: str) -> None:
        super().__init__("invalid_url", message, url=url)


class RobotsDisallowError(FetchTextError):
    def __init__(self, message: str, *, url: str) -> None:
        super().__init__("robots_disallow", message, url=url)


class FetchTimeoutError(FetchTextError):
    def __init__(self, message: str, *, url: str) -> None:
        super().__init__("timeout", message, url=url)


class HttpError(FetchTextError):
    def __init__(self, message: str, *, url: str, status_code: int | None = None) -> None:
        super().__init__("http_error", message, url=url, status_code=status_code)


class TooLargeError(FetchTextError):
    def __init__(self, message: str, *, url: str) -> None:
        super().__init__("too_large", message, url=url)


@dataclass(slots=True)
class _ClientBundle:
    client: httpx.Client
    robots: RobotsManager


_BUNDLES: dict[tuple[str, float], _ClientBundle] = {}
_BUNDLES_LOCK = threading.Lock()
_LAST_REQUEST_MONO_BY_HOST: dict[str, float] = {}
_PACE_LOCK = threading.Lock()
_HOST_SEMAPHORES: dict[str, threading.BoundedSemaphore] = {}
_HOST_SEMAPHORES_LOCK = threading.Lock()


def fetch_text(
    url: str,
    *,
    user_agent: str,
    timeout_s: float,
    max_bytes: int,
) -> tuple[int, str, str]:
    """Fetch text from URL with robots checks, pacing, redirects, and byte limits."""
    if timeout_s <= 0:
        raise ValueError("timeout_s must be > 0")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be > 0")
    if not user_agent:
        raise ValueError("user_agent must be non-empty")

    current_url = url
    redirects = 0

    while True:
        parsed, host = _validate_url(current_url)
        host_sem = _get_host_semaphore(host)
        bundle = _get_bundle(user_agent=user_agent, timeout_s=timeout_s)

        with host_sem:
            _pace(host)
            _enforce_robots(bundle.robots, current_url)
            try:
                with bundle.client.stream("GET", current_url) as resp:
                    status = resp.status_code
                    final_url = str(resp.url)
                    location = resp.headers.get("location")
                    if status in _REDIRECT_STATUSES and location:
                        if redirects >= _SETTINGS.max_redirects:
                            raise HttpError(
                                "redirect limit exceeded",
                                url=final_url,
                                status_code=status,
                            )
                        current_url = urljoin(final_url, location)
                        redirects += 1
                        continue

                    text = _read_text_limited(resp, max_bytes=max_bytes)
                    return status, final_url, text
            except TooLargeError:
                raise
            except httpx.TimeoutException as exc:
                raise FetchTimeoutError(str(exc), url=current_url) from exc
            except httpx.HTTPError as exc:
                raise HttpError(str(exc), url=current_url) from exc


def _get_bundle(*, user_agent: str, timeout_s: float) -> _ClientBundle:
    key = (user_agent, float(timeout_s))
    with _BUNDLES_LOCK:
        cached = _BUNDLES.get(key)
        if cached is not None:
            return cached

        client = httpx.Client(
            timeout=httpx.Timeout(timeout_s),
            follow_redirects=False,
            max_redirects=_SETTINGS.max_redirects,
            headers={"User-Agent": user_agent},
            transport=httpx.HTTPTransport(retries=_SETTINGS.connect_retries),
        )
        robots = RobotsManager(
            client=client,
            user_agent=user_agent,
            cache_ttl_seconds=_SETTINGS.robots_cache_ttl_seconds,
        )
        bundle = _ClientBundle(client=client, robots=robots)
        _BUNDLES[key] = bundle
        return bundle


def _enforce_robots(robots: RobotsManager, url: str) -> None:
    try:
        allowed = robots.can_fetch(url)
    except Exception as exc:
        raise RobotsDisallowError(f"robots check failed: {exc}", url=url) from exc
    if not allowed:
        raise RobotsDisallowError("blocked by robots.txt", url=url)


def _pace(host: str) -> None:
    min_interval_s = max(0.0, float(_SETTINGS.politeness_delay_seconds))
    if min_interval_s <= 0:
        return

    wait_s = 0.0
    now = time.monotonic()
    with _PACE_LOCK:
        last = _LAST_REQUEST_MONO_BY_HOST.get(host)
        if last is not None:
            wait_s = min_interval_s - (now - last)
        if wait_s > 0:
            # Reserve the slot before sleeping so concurrent callers queue on semaphore.
            _LAST_REQUEST_MONO_BY_HOST[host] = now + wait_s
        else:
            _LAST_REQUEST_MONO_BY_HOST[host] = now
    if wait_s > 0:
        time.sleep(wait_s)


def _get_host_semaphore(host: str) -> threading.BoundedSemaphore:
    with _HOST_SEMAPHORES_LOCK:
        sem = _HOST_SEMAPHORES.get(host)
        if sem is None:
            sem = threading.BoundedSemaphore(_HOST_MAX_CONCURRENCY)
            _HOST_SEMAPHORES[host] = sem
        return sem


def _validate_url(url: str) -> tuple[ParseResult, str]:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise InvalidUrlError("unsupported URL scheme", url=url)
    if not parsed.netloc:
        raise InvalidUrlError("missing URL host", url=url)
    if parsed.username or parsed.password:
        raise InvalidUrlError("URL userinfo is not allowed", url=url)

    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise InvalidUrlError("missing URL hostname", url=url)
    if host == "localhost" or host.endswith(".localhost"):
        raise InvalidUrlError("localhost is not allowed", url=url)

    try:
        port = _resolve_port(parsed)
    except ValueError as exc:
        raise InvalidUrlError(str(exc), url=url) from exc

    _enforce_ssrf(host=host, port=port, url=url)
    return parsed, host


def _resolve_port(parsed: ParseResult) -> int:
    if parsed.port is not None:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    return 80


def _enforce_ssrf(*, host: str, port: int, url: str) -> None:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        _check_dns_ips(host=host, port=port, url=url)
        return
    if not ip.is_global:
        raise InvalidUrlError(f"blocked IP address: {ip}", url=url)


def _check_dns_ips(*, host: str, port: int, url: str) -> None:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise InvalidUrlError(f"dns resolve failed: {exc}", url=url) from exc

    if not infos:
        raise InvalidUrlError("dns resolve returned no addresses", url=url)

    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_text = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError as exc:
            raise InvalidUrlError(f"invalid resolved IP: {ip_text}", url=url) from exc
        if not ip.is_global:
            raise InvalidUrlError(f"blocked resolved IP address: {ip}", url=url)


def _read_text_limited(resp: httpx.Response, *, max_bytes: int) -> str:
    chunks: list[bytes] = []
    total = 0
    for chunk in resp.iter_bytes():
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            raise TooLargeError(
                f"response body exceeds max_bytes={max_bytes}",
                url=str(resp.url),
            )
        chunks.append(chunk)

    body = b"".join(chunks)
    encoding = resp.encoding or "utf-8"
    return body.decode(encoding, errors="replace")


def _close_all_clients() -> None:
    with _BUNDLES_LOCK:
        bundles = list(_BUNDLES.values())
        _BUNDLES.clear()
    for bundle in bundles:
        try:
            bundle.client.close()
        except Exception:
            pass


atexit.register(_close_all_clients)
