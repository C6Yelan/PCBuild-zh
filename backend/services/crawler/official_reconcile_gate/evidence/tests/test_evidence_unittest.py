from __future__ import annotations

import unittest

from backend.services.crawler.official_reconcile_gate.evidence.fetch import (
    EvidenceFetchLimits,
    fetch_evidence,
)


class _FakeResponse:
    def __init__(self, status_code: int, headers: dict[str, str], chunks: list[bytes]) -> None:
        self.status_code = status_code
        self.headers = headers
        self._chunks = chunks

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def iter_bytes(self):
        for chunk in self._chunks:
            yield chunk


class _FakeClient:
    def __init__(self, response: _FakeResponse) -> None:
        self._response = response

    def stream(self, method: str, url: str, headers: dict[str, str] | None = None):
        return self._response


class TestEvidenceFetch(unittest.TestCase):
    def test_range_206_records_content_range_and_obeys_max_bytes(self) -> None:
        response = _FakeResponse(
            206,
            {
                "content-type": "text/html; charset=utf-8",
                "content-range": "bytes 0-999/9999",
            },
            [b"x" * 2000],
        )
        client = _FakeClient(response)
        result = fetch_evidence(
            "https://example.com/page",
            client,
            EvidenceFetchLimits(max_bytes=1024, snippet_bytes=128, timeout_seconds=1.0, max_redirects=1),
            allowed_hosts={"example.com"},
        )
        self.assertEqual(result.fetch_status, "too_large")
        self.assertEqual(result.content_range, "bytes 0-999/9999")
        self.assertEqual(result.bytes_read, 1024)

    def test_200_stream_reads_only_max_bytes(self) -> None:
        response = _FakeResponse(
            200,
            {"content-type": "text/html"},
            [b"a" * 700, b"b" * 700],
        )
        client = _FakeClient(response)
        result = fetch_evidence(
            "https://example.com/page",
            client,
            EvidenceFetchLimits(max_bytes=1024, snippet_bytes=256, timeout_seconds=1.0, max_redirects=1),
            allowed_hosts={"example.com"},
        )
        self.assertEqual(result.fetch_status, "too_large")
        self.assertEqual(result.bytes_read, 1024)

    def test_block_signature_cloudflare_and_waf(self) -> None:
        cloudflare = _FakeResponse(
            403,
            {"content-type": "text/html"},
            [b"<html><title>Attention Required</title>Cloudflare</html>"],
        )
        waf = _FakeResponse(
            403,
            {"content-type": "text/html"},
            [b"<html>Access Denied. verify you are human</html>"],
        )
        cloudflare_result = fetch_evidence(
            "https://example.com/cloudflare",
            _FakeClient(cloudflare),
            EvidenceFetchLimits(max_bytes=2048, snippet_bytes=512, timeout_seconds=1.0, max_redirects=1),
            allowed_hosts={"example.com"},
        )
        waf_result = fetch_evidence(
            "https://example.com/waf",
            _FakeClient(waf),
            EvidenceFetchLimits(max_bytes=2048, snippet_bytes=512, timeout_seconds=1.0, max_redirects=1),
            allowed_hosts={"example.com"},
        )
        self.assertEqual(cloudflare_result.block_reason, "cloudflare_interstitial")
        self.assertEqual(waf_result.block_reason, "waf_or_captcha")


if __name__ == "__main__":
    unittest.main()
