from __future__ import annotations

import unittest

from backend.services.crawler.official_reconcile_gate.evidence.types import FetchResult
from backend.tools.crawler import t6_fetch_candidate_evidence as evidence_cli


class TestEvidenceStatsClassification(unittest.TestCase):
    def test_too_large_200_206_count_as_ok_and_truncated(self) -> None:
        stats = {
            "total_candidates": 0,
            "to_fetch": 0,
            "skipped_robots": 0,
            "fetched_ok": 0,
            "fetched_truncated": 0,
            "fetched_http_error": 0,
            "fetched_unreachable": 0,
            "blocked_count": {},
            "bytes_read_total": 0,
            "errors_count": 0,
        }
        too_large_206 = FetchResult(
            fetch_status="too_large",
            http_status_code=206,
            final_url="https://example.com/a",
            content_type="text/html",
            content_length=None,
            content_range="bytes 0-1023/99999",
            server=None,
            cache_control=None,
            body_sha256="a",
            body_snippet="x",
            block_reason=None,
            bytes_read=1024,
            error=None,
        )
        too_large_200 = FetchResult(
            fetch_status="too_large",
            http_status_code=200,
            final_url="https://example.com/b",
            content_type="text/html",
            content_length=None,
            content_range=None,
            server=None,
            cache_control=None,
            body_sha256="b",
            body_snippet="x",
            block_reason=None,
            bytes_read=1024,
            error=None,
        )

        evidence_cli._accumulate_fetch_stats(stats, too_large_206)
        evidence_cli._accumulate_fetch_stats(stats, too_large_200)

        self.assertEqual(stats["fetched_ok"], 2)
        self.assertEqual(stats["fetched_truncated"], 2)
        self.assertEqual(stats["fetched_http_error"], 0)
        self.assertEqual(stats["fetched_unreachable"], 0)
        self.assertEqual(stats["bytes_read_total"], 2048)

    def test_http_error_stays_in_http_error_bucket(self) -> None:
        stats = {
            "total_candidates": 0,
            "to_fetch": 0,
            "skipped_robots": 0,
            "fetched_ok": 0,
            "fetched_truncated": 0,
            "fetched_http_error": 0,
            "fetched_unreachable": 0,
            "blocked_count": {},
            "bytes_read_total": 0,
            "errors_count": 0,
        }
        http_error = FetchResult(
            fetch_status="http_error",
            http_status_code=503,
            final_url="https://example.com/error",
            content_type="text/html",
            content_length=None,
            content_range=None,
            server=None,
            cache_control=None,
            body_sha256=None,
            body_snippet="",
            block_reason=None,
            bytes_read=0,
            error="status_503",
        )
        unreachable = FetchResult(
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
            error="timeout",
        )

        evidence_cli._accumulate_fetch_stats(stats, http_error)
        evidence_cli._accumulate_fetch_stats(stats, unreachable)

        self.assertEqual(stats["fetched_ok"], 0)
        self.assertEqual(stats["fetched_truncated"], 0)
        self.assertEqual(stats["fetched_http_error"], 1)
        self.assertEqual(stats["fetched_unreachable"], 1)


if __name__ == "__main__":
    unittest.main()
