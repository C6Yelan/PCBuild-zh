# backend/services/crawler/official_reconcile_gate/fetch.py
from __future__ import annotations

import ipaddress
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

        parsed = _validate_url(url)
        _guard_ssrf_host(parsed.hostname or "")

        try:
            resp = self._client.get(url)
        except httpx.HTTPError as e:
            raise FetchError(str(e)) from e

        return FetchedResponse(
            url=url,
            final_url=str(resp.url),
            status_code=resp.status_code,
            fetched_at=datetime.now(timezone.utc).isoformat(),
            headers={k.lower(): v for k, v in resp.headers.items()},
            body=resp.content,
        )

    def _build_client(self):
        if httpx is None:
            return None
        return httpx.Client(
            follow_redirects=True,
            timeout=httpx.Timeout(self._timeout_seconds),
            max_redirects=self._max_redirects,
            headers={"User-Agent": self._user_agent},
        )


_ALLOWED_SCHEMES = ("http", "https")


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


def _guard_ssrf_host(hostname: str) -> None:
    host = (hostname or "").strip().lower()
    if not host:
        raise FetchError("URL missing hostname")

    if host == "localhost" or host.endswith(".localhost"):
        raise SSRFBlockedError(f"blocked hostname: {host}")

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return

    if _ip_blocked(ip):
        raise SSRFBlockedError(f"blocked IP address: {ip}")


def _ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )
