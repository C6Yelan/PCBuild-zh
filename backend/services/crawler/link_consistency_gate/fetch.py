# backend/services/crawler/link_consistency_gate/fetch.py
from __future__ import annotations

import ipaddress
import random
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from .types import FetchConfig, PacingConfig


class SSRFBlockedError(RuntimeError): # 當 URL 觸發 SSRF 規則（例如 localhost、私有網段、DNS 解析到內網 IP）就丟這個例外，讓上層把它視為安全性阻擋。
    pass


class RedirectLimitError(RuntimeError): # 手動追 redirect 超過 fetch.max_redirects 就丟，避免無限轉址循環。
    pass


@dataclass(frozen=True)
class FetchMeta:
    warnings: list[str] # 例如 ["TRUNCATED"]，代表內容被截斷了（超過 max_bytes）。
    redirect_chain: list[str] # 記錄每次遇到 redirect 時「當下的 resp.url」


class Fetcher:
    """
    Fetch層(類別無關)。
    - 重用 engine 提供的 httpx.Client
    - SSRF 防護（scheme + hostname/IP 檢查，包括 DNS 解析）
    - 每 host 的禮貌性 pacing
    - 保守的 max_bytes 處理（不直接用 httpx 的 response.read()，而是自己控制讀取多少 bytes，超過就丟掉剩下的）。
    """

    def __init__(self, client: httpx.Client, *, fetch: FetchConfig, pacing: PacingConfig) -> None: # 維護 per-host 節流與並行控制需要一些狀態，所以用 instance 來包裝。
        self._client = client
        self._fetch = fetch
        self._pacing = pacing

        self._lock = threading.Lock() # 保護 _next_allowed_mono_by_host 和 _sem_by_host 的 thread-safe 存取。
        self._next_allowed_mono_by_host: dict[str, float] = {} # host -> 下一次允許發 request 的 monotonic 時間（秒）。
        self._sem_by_host: dict[str, threading.BoundedSemaphore] = {} # host -> 控制同時對該 host 發 request 的最大併發數的號誌(semaphore)。
        self._last_meta: Optional[FetchMeta] = None # 保存上一筆 fetch 的 meta，讓上層用 pop_last_meta() 取走。

    def pop_last_meta(self) -> FetchMeta: # 讓上層在 fetch 之後取走 meta（warnings, redirect_chain），取一次就丟，下一次如果沒 fetch 就回傳空的 meta。
        meta = self._last_meta or FetchMeta(warnings=[], redirect_chain=[])
        self._last_meta = None
        return meta

    def fetch(self, url: str) -> tuple[str, int, bytes, int]: # 核心抓取流程，回傳 (final_url, status_code, body_bytes, elapsed_ms)，過程中會更新 self._last_meta。
        self._last_meta = None
        start = time.monotonic()

        redirect_chain: list[str] = []
        warnings: list[str] = []

        current = url
        redirects = 0

        while True:
            parsed = _validate_url_basic(current)
            host = parsed.hostname or ""
            _enforce_ssrf(host, scheme=parsed.scheme, port=parsed.port)

            sem = self._get_host_semaphore(host)
            sem.acquire()
            try:
                self._pace(host)
                timeout = httpx.Timeout(self._fetch.timeout_s)
                with self._client.stream("GET", current, follow_redirects=False, timeout=timeout) as resp:
                    status = resp.status_code
                    location = resp.headers.get("location")
                    if status in (301, 302, 303, 307, 308) and location:
                        redirect_chain.append(str(resp.url))
                        if redirects >= self._fetch.max_redirects:
                            raise RedirectLimitError(f"max redirects exceeded ({self._fetch.max_redirects})")
                        current = urljoin(str(resp.url), location)
                        redirects += 1
                        continue

                    body, truncated = _read_limited(resp, max_bytes=self._fetch.max_bytes)
                    if truncated:
                        warnings.append("TRUNCATED")

                    final_url = str(resp.url)
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    self._last_meta = FetchMeta(warnings=warnings, redirect_chain=redirect_chain)
                    return final_url, status, body, elapsed_ms
            finally:
                sem.release()

    def _pace(self, host: str) -> None: # 根據 host 的節流設定，控制請求的最小間隔時間，並加入隨機抖動。
        min_interval_ms = max(0, int(self._pacing.min_interval_ms)) # 控制同一個 host 的請求之間至少要間隔多少毫秒，避免過度頻繁地請求同一個 host 造成負擔或被封鎖。
        if min_interval_ms <= 0 or not host:
            return

        jitter_ms = max(0, int(self._pacing.jitter_ms)) # 隨機抖動的最大毫秒數，實際的抖動時間會在 0 到 jitter_ms 之間隨機選擇，讓請求時間更分散，減少被對方識別為機器行為的風險。
        jitter_s = (random.randint(0, jitter_ms) / 1000.0) if jitter_ms > 0 else 0.0
        min_interval_s = min_interval_ms / 1000.0

        with self._lock:
            now = time.monotonic()
            next_allowed = self._next_allowed_mono_by_host.get(host, 0.0)
            scheduled = max(now, next_allowed) + jitter_s
            wait_s = scheduled - now
            self._next_allowed_mono_by_host[host] = scheduled + min_interval_s

        if wait_s > 0:
            time.sleep(wait_s)

    def _get_host_semaphore(self, host: str) -> threading.BoundedSemaphore: # 根據 host 的併發限制，取得對該 host 發 request 的 semaphore，第一次見到的 host 就創一個新的 semaphore。
        max_c = max(1, int(self._pacing.max_concurrency_per_host))
        with self._lock:
            sem = self._sem_by_host.get(host)
            if sem is None:
                sem = threading.BoundedSemaphore(value=max_c)
                self._sem_by_host[host] = sem
            return sem


def _validate_url_basic(url: str): # URL 基本格式檢查：scheme 必須是 http 或 https，必須有 host，不能有 userinfo（username/password）。
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported URL scheme: {parsed.scheme!r}")
    if not parsed.netloc:
        raise ValueError("URL missing host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL must not contain userinfo")
    return parsed


def _enforce_ssrf(hostname: str, *, scheme: str, port: Optional[int]) -> None: # SSRF 防護：禁止 localhost、私有網段，對 hostname 做 DNS 解析後也要檢查 IP。
    host = (hostname or "").strip().lower()
    if not host:
        raise ValueError("URL missing hostname")
    if host == "localhost" or host.endswith(".localhost"):
        raise SSRFBlockedError(f"blocked hostname: {host}")

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        _check_dns_ips(host, port=_resolve_port(scheme, port))
        return

    if _ip_blocked(ip):
        raise SSRFBlockedError(f"blocked IP address: {ip}")


def _check_dns_ips(host: str, *, port: int) -> None: # DNS 解析後檢查 IP 是否被封鎖
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as e:
        raise ValueError(f"DNS resolution failed for host {host!r}: {e}") from e

    for info in infos:
        sockaddr = info[4]
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _ip_blocked(ip):
            raise SSRFBlockedError(f"blocked resolved IP address: {ip} (host={host!r})")


def _resolve_port(scheme: str, port: Optional[int]) -> int: 
    # 根據 URL 的 scheme 和 port，決定實際要連的 port。URL 中如果有明確指定 port 就用它，沒有的話 http 預設 80，https 預設 443。
    if port is not None:
        return int(port)
    return 443 if (scheme or "").lower() == "https" else 80


def _ip_blocked(ip: ipaddress._BaseAddress) -> bool:
    # 保守起見：拒絕任何非全球可路由地址。
    if getattr(ip, "is_global", False) is True:
        return False
    return True


def _read_limited(resp: httpx.Response, *, max_bytes: int) -> tuple[bytes, bool]: 
    # 從 response 以 chunk 方式讀取內容，最多讀 max_bytes，超過就丟掉剩下的並回傳 truncated=True。這樣做比直接用 resp.read() 更能控制 memory usage，避免抓超大檔案時吃光記憶體。
    limit = max(0, int(max_bytes))
    buf = bytearray()
    truncated = False

    if limit == 0:
        for _ in resp.iter_bytes():
            truncated = True
            break
        return b"", truncated

    for chunk in resp.iter_bytes():
        if not chunk:
            continue
        remaining = limit - len(buf)
        if remaining <= 0:
            truncated = True
            break
        if len(chunk) <= remaining:
            buf.extend(chunk)
            continue
        buf.extend(chunk[:remaining])
        truncated = True
        break

    return bytes(buf), truncated
