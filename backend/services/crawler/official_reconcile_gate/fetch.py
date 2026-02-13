# backend/services/crawler/official_reconcile_gate/fetch.py
from __future__ import annotations

import ipaddress
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import httpx
except ModuleNotFoundError:  # pragma: no cover - optional runtime dependency in lightweight envs
    httpx = None  # type: ignore[assignment]

from .types import FetchedResponse


class FetchError(RuntimeError):
    pass


class UnsupportedSchemeError(FetchError):
    pass


class SSRFBlockedError(FetchError):
    pass


def default_user_agent() -> str:
    try:
        from backend.services.crawler.config import CrawlerSettings

        return CrawlerSettings().user_agent
    except Exception:
        return "pcbuild-zh-crawler/0.1 (+contact: admin@localhost)"


class OfficialFetcher:
    def __init__(
        self,
        *,
        timeout_seconds: float = 5.0,
        user_agent: str | None = None,
        max_redirects: int = 5,
    ) -> None:
        ua = (user_agent or "").strip() or default_user_agent()
        self._timeout_seconds = timeout_seconds
        self._max_redirects = max_redirects
        self._user_agent = ua
        self._client = self._build_client()

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    def __enter__(self) -> "OfficialFetcher":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def fetch(self, url: str) -> FetchedResponse:
        if self._client is None:
            raise FetchError("httpx is required for fetch operations")

        current_url = url
        redirects = 0

        while True:
            _guard_ssrf_url(current_url)

            try:
                resp = self._client.get(current_url, follow_redirects=False)
            except httpx.HTTPError as e:
                raise FetchError(str(e)) from e

            location = resp.headers.get("location")
            if _is_redirect_response(resp.status_code) and location:
                if redirects >= self._max_redirects:
                    raise FetchError("too many redirects")

                try:
                    next_url = str(httpx.URL(current_url).join(location))
                except Exception as e:
                    raise FetchError(f"invalid redirect location: {location!r}") from e

                _guard_ssrf_url(next_url)
                current_url = next_url
                redirects += 1
                continue

            final_url = str(resp.url) if str(resp.url) else current_url
            _guard_ssrf_url(final_url)
            return FetchedResponse(
                url=url,
                final_url=final_url,
                status_code=resp.status_code,
                fetched_at=datetime.now(timezone.utc).isoformat(),
                headers={k.lower(): v for k, v in resp.headers.items()},
                body=resp.content,
            )

    def _build_client(self):
        if httpx is None:
            return None
        return httpx.Client(
            follow_redirects=False,
            timeout=httpx.Timeout(self._timeout_seconds),
            max_redirects=self._max_redirects,
            headers={"User-Agent": self._user_agent},
        )


_ALLOWED_SCHEMES = ("http", "https")
_REDIRECT_STATUS_CODES = frozenset((301, 302, 303, 307, 308))


def _is_redirect_response(status_code: int) -> bool:
    return status_code in _REDIRECT_STATUS_CODES


def _validate_url(url: str):
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise UnsupportedSchemeError(f"unsupported URL scheme: {scheme!r}")
    if not parsed.netloc:
        raise FetchError("URL missing host")
    if parsed.username is not None or parsed.password is not None:
        raise FetchError("URL must not contain userinfo")
    return parsed


def _guard_ssrf_url(url: str) -> None:
    parsed = _validate_url(url)
    _guard_ssrf_host(parsed.hostname or "")


def _guard_ssrf_host(hostname: str) -> None:
    host = _normalize_hostname(hostname)
    if not host:
        raise FetchError("URL missing hostname")

    if host == "localhost" or host.endswith(".localhost"):
        raise SSRFBlockedError(f"blocked hostname: {host}")

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        _guard_ssrf_dns(host)
        return

    if _ip_blocked(ip):
        raise SSRFBlockedError(f"blocked IP address: {ip}")


def _normalize_hostname(hostname: str) -> str:
    return (hostname or "").strip().lower().rstrip(".")


def _to_idna_ascii(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise FetchError(f"invalid hostname: {host!r}") from e


def _guard_ssrf_dns(host: str) -> None:
    ascii_host = _to_idna_ascii(host)
    try:
        infos = socket.getaddrinfo(ascii_host, None, type=socket.SOCK_STREAM)
    except OSError as e:
        raise FetchError(f"DNS lookup failed for host {host!r}: {e}") from e

    if not infos:
        raise FetchError(f"DNS lookup returned no addresses for host {host!r}")

    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_text = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            continue
        if _ip_blocked(ip):
            raise SSRFBlockedError(f"blocked resolved IP address: {ip} (host={host!r})")


def _ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )
