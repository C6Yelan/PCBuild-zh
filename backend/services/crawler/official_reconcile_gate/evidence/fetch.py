from __future__ import annotations

import hashlib
import ipaddress
import socket
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

try:
    import httpx
except ModuleNotFoundError:  # pragma: no cover - runtime dependency guard
    httpx = None  # type: ignore[assignment]

from .types import BlockSignature, FetchResult

_REDIRECT_CODES = {301, 302, 303, 307, 308}
_BLOCK_SIGNATURE_CLOUDFLARE = BlockSignature(
    name="cloudflare_interstitial",
    keywords=("attention required", "cloudflare"),
)
_BLOCK_SIGNATURE_WAF = BlockSignature(
    name="waf_or_captcha",
    keywords=("captcha", "verify you are human", "access denied"),
)


@dataclass(frozen=True)
class EvidenceFetchLimits:
    max_bytes: int = 131_072
    snippet_bytes: int = 4096
    timeout_seconds: float = 10.0
    max_redirects: int = 5


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


class _TooLargeError(RuntimeError):
    pass


def fetch_evidence(
    url: str,
    client: Any,
    limits: EvidenceFetchLimits,
    *,
    allowed_hosts: set[str] | None = None,
) -> FetchResult:
    validation_error = _validate_target_url(url, allowed_hosts=allowed_hosts)
    if validation_error is not None:
        return FetchResult(
            fetch_status="invalid_url",
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
            bytes_read=0,
            error=validation_error,
        )

    if hasattr(client, "stream"):
        return _fetch_with_httpx(url, client=client, limits=limits, allowed_hosts=allowed_hosts)
    return _fetch_with_urllib(url, opener=client, limits=limits, allowed_hosts=allowed_hosts)


def build_evidence_http_client(limits: EvidenceFetchLimits) -> Any:
    if httpx is None:
        return build_opener(_NoRedirectHandler())
    timeout = httpx.Timeout(
        limits.timeout_seconds,
        connect=limits.timeout_seconds,
        read=limits.timeout_seconds,
    )
    return httpx.Client(timeout=timeout, follow_redirects=False)


def close_evidence_http_client(client: Any) -> None:
    close_fn = getattr(client, "close", None)
    if callable(close_fn):
        close_fn()


def _fetch_with_httpx(
    url: str,
    *,
    client: Any,
    limits: EvidenceFetchLimits,
    allowed_hosts: set[str] | None,
) -> FetchResult:
    current_url = url
    headers = {"Range": f"bytes=0-{limits.max_bytes - 1}"}

    for _ in range(limits.max_redirects + 1):
        validation_error = _validate_target_url(current_url, allowed_hosts=allowed_hosts)
        if validation_error is not None:
            return _invalid_url_result(validation_error)

        try:
            with client.stream("GET", current_url, headers=headers) as response:
                status_code = int(response.status_code)
                if status_code in _REDIRECT_CODES:
                    location = response.headers.get("location", "")
                    if not location:
                        return _unreachable_result(error="redirect_without_location")
                    current_url = urljoin(current_url, location)
                    continue

                raw_bytes, truncated = _read_httpx_bytes(response, max_bytes=limits.max_bytes)
                return _build_fetch_result(
                    status_code=status_code,
                    final_url=current_url,
                    headers=response.headers,
                    body=raw_bytes,
                    truncated=truncated,
                    snippet_bytes=limits.snippet_bytes,
                )
        except _TooLargeError:
            return _too_large_result()
        except httpx.TimeoutException as exc:
            return _unreachable_result(error=f"timeout:{exc}")
        except httpx.RequestError as exc:
            return _unreachable_result(error=f"request_error:{exc}")

    return _unreachable_result(error=f"redirects>{limits.max_redirects}")


def _fetch_with_urllib(
    url: str,
    *,
    opener: Any,
    limits: EvidenceFetchLimits,
    allowed_hosts: set[str] | None,
) -> FetchResult:
    current_url = url
    range_header = f"bytes=0-{limits.max_bytes - 1}"

    for _ in range(limits.max_redirects + 1):
        validation_error = _validate_target_url(current_url, allowed_hosts=allowed_hosts)
        if validation_error is not None:
            return _invalid_url_result(validation_error)

        request = Request(current_url, method="GET", headers={"Range": range_header})
        try:
            with opener.open(request, timeout=limits.timeout_seconds) as response:
                status_code = int(getattr(response, "status", response.getcode()))
                if status_code in _REDIRECT_CODES:
                    location = response.headers.get("Location", "")
                    if not location:
                        return _unreachable_result(error="redirect_without_location")
                    current_url = urljoin(current_url, location)
                    continue

                raw_bytes, truncated = _read_urllib_bytes(response, max_bytes=limits.max_bytes)
                return _build_fetch_result(
                    status_code=status_code,
                    final_url=current_url,
                    headers=response.headers,
                    body=raw_bytes,
                    truncated=truncated,
                    snippet_bytes=limits.snippet_bytes,
                )
        except HTTPError as exc:
            if exc.code in _REDIRECT_CODES:
                location = exc.headers.get("Location", "") if exc.headers else ""
                if not location:
                    return _unreachable_result(error="redirect_without_location")
                current_url = urljoin(current_url, location)
                continue
            headers = exc.headers if exc.headers is not None else {}
            payload = b""
            if hasattr(exc, "read"):
                try:
                    payload, _ = _read_urllib_bytes(exc, max_bytes=limits.max_bytes)
                except Exception:
                    payload = b""
            return _build_fetch_result(
                status_code=int(exc.code),
                final_url=current_url,
                headers=headers,
                body=payload,
                truncated=False,
                snippet_bytes=limits.snippet_bytes,
            )
        except _TooLargeError:
            return _too_large_result()
        except (socket.timeout, TimeoutError) as exc:
            return _unreachable_result(error=f"timeout:{exc}")
        except URLError as exc:
            return _unreachable_result(error=f"request_error:{exc.reason}")

    return _unreachable_result(error=f"redirects>{limits.max_redirects}")


def _read_httpx_bytes(response: Any, *, max_bytes: int) -> tuple[bytes, bool]:
    out = bytearray()
    truncated = False
    for chunk in response.iter_bytes():
        if not chunk:
            continue
        remaining = max_bytes - len(out)
        if remaining <= 0:
            truncated = True
            break
        if len(chunk) > remaining:
            out.extend(chunk[:remaining])
            truncated = True
            break
        out.extend(chunk)
        if len(out) >= max_bytes:
            # Could still be complete; do not read more to enforce hard cap.
            break
    return (bytes(out), truncated)


def _read_urllib_bytes(response: Any, *, max_bytes: int) -> tuple[bytes, bool]:
    out = bytearray()
    truncated = False
    while True:
        chunk = response.read(min(65536, max_bytes + 1))
        if not chunk:
            break
        remaining = max_bytes - len(out)
        if remaining <= 0:
            truncated = True
            break
        if len(chunk) > remaining:
            out.extend(chunk[:remaining])
            truncated = True
            break
        out.extend(chunk)
        if len(out) >= max_bytes:
            break
    return (bytes(out), truncated)


def _build_fetch_result(
    *,
    status_code: int,
    final_url: str,
    headers: Any,
    body: bytes,
    truncated: bool,
    snippet_bytes: int,
) -> FetchResult:
    content_type = _header_value(headers, "content-type")
    snippet = _decode_snippet(body[:snippet_bytes])
    sha256 = hashlib.sha256(body).hexdigest()
    block_reason = _detect_block_reason(status_code, content_type or "", snippet)

    if truncated:
        status = "too_large"
    elif 200 <= status_code < 300:
        status = "fetched"
    elif status_code >= 400:
        status = "http_error"
    else:
        status = "http_error"

    return FetchResult(
        fetch_status=status,
        http_status_code=status_code,
        final_url=final_url,
        content_type=content_type,
        content_length=_header_value(headers, "content-length"),
        content_range=_header_value(headers, "content-range"),
        server=_header_value(headers, "server"),
        cache_control=_header_value(headers, "cache-control"),
        body_sha256=sha256,
        body_snippet=snippet,
        block_reason=block_reason,
        bytes_read=len(body),
        error=None,
    )


def _header_value(headers: Any, name: str) -> str | None:
    if headers is None:
        return None
    value = None
    if hasattr(headers, "get"):
        value = headers.get(name) or headers.get(name.title())
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _decode_snippet(body_bytes: bytes) -> str:
    if not body_bytes:
        return ""
    try:
        return body_bytes.decode("utf-8-sig", "ignore")
    except Exception:
        return body_bytes.decode("utf-8", "ignore")


def _detect_block_reason(status_code: int | None, content_type: str, snippet: str) -> str | None:
    content_type_lower = (content_type or "").lower()
    if content_type_lower and "html" not in content_type_lower and not content_type_lower.startswith("text/"):
        return None

    snippet_lower = (snippet or "").lower()
    if status_code in (403, 429, 503):
        if all(keyword in snippet_lower for keyword in _BLOCK_SIGNATURE_CLOUDFLARE.keywords):
            return _BLOCK_SIGNATURE_CLOUDFLARE.name
    if any(keyword in snippet_lower for keyword in _BLOCK_SIGNATURE_WAF.keywords):
        return _BLOCK_SIGNATURE_WAF.name
    return None


def _invalid_url_result(reason: str) -> FetchResult:
    return FetchResult(
        fetch_status="invalid_url",
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
        bytes_read=0,
        error=reason,
    )


def _unreachable_result(*, error: str) -> FetchResult:
    return FetchResult(
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
        bytes_read=0,
        error=error,
    )


def _too_large_result() -> FetchResult:
    return FetchResult(
        fetch_status="too_large",
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
        bytes_read=0,
        error="too_large",
    )


def _validate_target_url(url: str, *, allowed_hosts: set[str] | None) -> str | None:
    parsed = urlsplit((url or "").strip())
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
