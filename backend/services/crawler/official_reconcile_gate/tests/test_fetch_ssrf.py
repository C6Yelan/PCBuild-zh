# backend/services/crawler/official_reconcile_gate/tests/test_fetch_ssrf.py
from __future__ import annotations

import socket
import unittest
from unittest import mock

from backend.services.crawler.official_reconcile_gate import fetch as fetch_mod
from backend.services.crawler.official_reconcile_gate.fetch import OfficialFetcher, SSRFBlockedError


@unittest.skipIf(fetch_mod.httpx is None, "httpx is not available in this environment")
class OfficialFetcherSSRFTests(unittest.TestCase):
    def test_block_localhost_and_loopback(self) -> None:
        with OfficialFetcher(timeout_seconds=1.0) as fetcher:
            with self.assertRaises(SSRFBlockedError):
                fetcher.fetch("http://127.0.0.1")
            with self.assertRaises(SSRFBlockedError):
                fetcher.fetch("http://localhost")

    def test_dns_rebind_blocks_private_ip_without_network(self) -> None:
        assert fetch_mod.httpx is not None

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            if str(host).lower().rstrip(".") == "example.com":
                return [
                    (
                        socket.AF_INET,
                        socket.SOCK_STREAM,
                        socket.IPPROTO_TCP,
                        "",
                        ("10.0.0.1", 0),
                    )
                ]
            raise AssertionError(f"unexpected host lookup: {host!r}")

        req = fetch_mod.httpx.Request("GET", "https://example.com/")
        ok_resp = fetch_mod.httpx.Response(
            200,
            request=req,
            headers={"content-type": "text/plain"},
            content=b"ok",
        )

        with (
            mock.patch.object(socket, "getaddrinfo", side_effect=fake_getaddrinfo),
            mock.patch.object(fetch_mod.httpx.Client, "get", return_value=ok_resp),
        ):
            with OfficialFetcher(timeout_seconds=1.0) as fetcher:
                with self.assertRaises(SSRFBlockedError):
                    fetcher.fetch("https://example.com/")

    def test_redirect_to_loopback_is_blocked_before_second_request(self) -> None:
        assert fetch_mod.httpx is not None

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            if str(host).lower().rstrip(".") == "example.com":
                return [
                    (
                        socket.AF_INET,
                        socket.SOCK_STREAM,
                        socket.IPPROTO_TCP,
                        "",
                        ("93.184.216.34", 0),
                    )
                ]
            raise AssertionError(f"unexpected host lookup: {host!r}")

        def fake_get(_self, url, *args, **kwargs):
            req = fetch_mod.httpx.Request("GET", url)
            if url == "https://example.com/start":
                return fetch_mod.httpx.Response(
                    302,
                    request=req,
                    headers={"location": "http://127.0.0.1:1"},
                )
            raise RuntimeError("should not send second request")

        with (
            mock.patch.object(socket, "getaddrinfo", side_effect=fake_getaddrinfo),
            mock.patch.object(fetch_mod.httpx.Client, "get", autospec=True, side_effect=fake_get) as mock_get,
        ):
            with OfficialFetcher(timeout_seconds=1.0) as fetcher:
                with self.assertRaises(SSRFBlockedError):
                    fetcher.fetch("https://example.com/start")

            self.assertEqual(mock_get.call_count, 1)


if __name__ == "__main__":
    unittest.main()
