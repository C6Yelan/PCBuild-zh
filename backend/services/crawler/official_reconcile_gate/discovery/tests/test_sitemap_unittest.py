from __future__ import annotations

import unittest
from unittest import mock

from backend.services.crawler.official_reconcile_gate.discovery import discover as discover_mod
from backend.services.crawler.official_reconcile_gate.discovery.discover import (
    classify_discovery_error,
    discover_candidates_from_plans,
    parse_robots_sitemaps,
    score_candidate_urls,
)
from backend.services.crawler.official_reconcile_gate.discovery.sitemap import SitemapParseError, parse_sitemap
from backend.services.crawler.official_reconcile_gate.planning.types import BrandRegistryEntry, OfficialRegistry


class _FakeHTTPResponse:
    def __init__(self, payload: bytes, *, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self._payload = payload
        self._offset = 0
        self.status = status
        self.headers = headers or {"Content-Type": "application/xml"}

    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def read(self, size: int = -1) -> bytes:
        if self._offset >= len(self._payload):
            return b""
        if size is None or size < 0:
            size = len(self._payload) - self._offset
        start = self._offset
        end = min(len(self._payload), start + size)
        self._offset = end
        return self._payload[start:end]

    def getcode(self) -> int:
        return self.status


class _FakeUrlLibOpener:
    def __init__(self, payload: bytes, *, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self._payload = payload
        self._status = status
        self._headers = headers or {"Content-Type": "application/xml"}

    def open(self, request, timeout: float | None = None) -> _FakeHTTPResponse:  # noqa: ANN001
        return _FakeHTTPResponse(self._payload, status=self._status, headers=dict(self._headers))


def _build_large_urlset_bytes(*, min_size: int) -> bytes:
    header = b'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    footer = b"</urlset>"
    body = bytearray()
    index = 0
    while len(header) + len(body) + len(footer) < min_size:
        body.extend(f"<url><loc>https://example.com/products/item-{index:06d}</loc></url>".encode("utf-8"))
        index += 1
    return header + bytes(body) + footer


def _build_large_non_sitemap_bytes(*, min_size: int) -> bytes:
    return b"X" * min_size


class TestSitemapParserAndScoring(unittest.TestCase):
    def test_parse_urlset_returns_all_loc(self) -> None:
        xml = b"""\xef\xbb\xbf \n<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/p/a</loc></url>
  <url><loc>https://example.com/p/b</loc></url>
</urlset>
"""
        kind, urls = parse_sitemap(xml)
        self.assertEqual(kind, "urlset")
        self.assertEqual(urls, ["https://example.com/p/a", "https://example.com/p/b"])

    def test_parse_sitemap_index_returns_child_sitemaps(self) -> None:
        xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://example.com/sitemap-products.xml</loc></sitemap>
  <sitemap><loc>https://example.com/sitemap-blog.xml.gz</loc></sitemap>
</sitemapindex>
"""
        kind, urls = parse_sitemap(xml)
        self.assertEqual(kind, "index")
        self.assertEqual(
            urls,
            [
                "https://example.com/sitemap-products.xml",
                "https://example.com/sitemap-blog.xml.gz",
            ],
        )

    def test_score_candidate_urls_topk_is_deterministic(self) -> None:
        urls = [
            "https://example.com/products/abc-123",
            "https://example.com/products/abc",
            "https://example.com/products/xyz",
            "https://example.com/products/abc-123-z",
        ]
        query_terms = ["abc", "123"]

        ranked = score_candidate_urls(urls, query_terms, topk=3, min_score=1)
        self.assertEqual(ranked[0][0], "https://example.com/products/abc-123")
        self.assertEqual(ranked[0][1], 2)
        self.assertEqual(ranked[0][2], ["abc", "123"])
        self.assertEqual(ranked[1][0], "https://example.com/products/abc-123-z")
        self.assertEqual(ranked[1][1], 2)
        self.assertEqual(ranked[2][0], "https://example.com/products/abc")
        self.assertEqual(ranked[2][1], 1)

    def test_unknown_root_returns_unknown_root_error(self) -> None:
        with self.assertRaises(SitemapParseError) as ctx:
            parse_sitemap(b"<feed xmlns='http://www.w3.org/2005/Atom'></feed>")
        self.assertEqual(ctx.exception.reason, "unknown_root")

    def test_min_score_filters_out_non_matches(self) -> None:
        xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/products/prime-b760m</loc></url>
  <url><loc>https://example.com/products/x670e</loc></url>
</urlset>
"""
        _, urls = parse_sitemap(xml)
        ranked = score_candidate_urls(urls, ["focus gx-750"], topk=5, min_score=1)
        self.assertEqual(ranked, [])

    def test_token_scoring_matches_focus_gx_path(self) -> None:
        xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://seasonic.com/products/focus-gx/</loc></url>
  <url><loc>https://seasonic.com/products/vertex/</loc></url>
</urlset>
"""
        _, urls = parse_sitemap(xml)
        ranked = score_candidate_urls(urls, ["FOCUS GX-750"], topk=5, min_score=1)
        self.assertEqual(ranked[0][0], "https://seasonic.com/products/focus-gx/")
        self.assertEqual(ranked[0][1], 1)
        self.assertEqual(ranked[0][2], ["focus"])

    def test_classify_discovery_error_cloudflare_403_blocked(self) -> None:
        reason, detail = classify_discovery_error(
            403,
            {"server": "cloudflare", "cf-ray": "xxx"},
        )
        self.assertEqual(reason, "blocked")
        self.assertEqual(detail, "cloudflare_403")

    def test_classify_discovery_error_plain_403_stays_http_status(self) -> None:
        reason, detail = classify_discovery_error(
            403,
            {"server": "nginx"},
        )
        self.assertEqual(reason, "http_status")
        self.assertEqual(detail, "403")

    def test_registry_entrypoint_failure_fallbacks_to_default_entrypoints(self) -> None:
        plans = [
            {
                "retail_url": "https://example.invalid/psu/1",
                "source": "coolpc",
                "category": "PSU",
                "title": "Seasonic FOCUS GX-750",
                "sku_hint": "FOCUS GX-750",
                "brand_key": "seasonic",
                "brand_source": "title_or_sku_hint+registry_alias",
                "brand_raw": "seasonic",
                "allowed_domains": ["example.com"],
                "query_terms": ["FOCUS GX-750"],
                "decision": "ok",
                "decision_notes": "ok",
            }
        ]
        registry = OfficialRegistry(
            version=1,
            brands=[
                BrandRegistryEntry(
                    brand_key="seasonic",
                    brand_aliases=["Seasonic"],
                    allowed_domains=["example.com"],
                    sitemap_urls=["https://example.com/custom-seed.xml"],
                )
            ],
            alias_map={"SEASONIC": "seasonic"},
        )

        def fake_fetch_and_parse_sitemap(
            *,
            client,
            sitemap_url: str,
            allowed_hosts: set[str],
            timeout_seconds: float,
            max_bytes: int,
            max_redirects: int,
        ) -> tuple[str, list[str], int]:
            if sitemap_url == "https://example.com/custom-seed.xml":
                raise discover_mod._SitemapFetchError("http_status", "404", request_count=1)
            if sitemap_url == "https://example.com/sitemap_index.xml":
                return ("index", ["https://example.com/products.xml"], 1)
            if sitemap_url == "https://example.com/products.xml":
                return ("urlset", ["https://example.com/products/focus-gx-750"], 1)
            raise discover_mod._SitemapFetchError("http_status", "404", request_count=1)

        with mock.patch.object(discover_mod, "_build_fetch_client", return_value=object()), mock.patch.object(
            discover_mod, "_close_fetch_client", return_value=None
        ), mock.patch.object(discover_mod, "_fetch_and_parse_sitemap", side_effect=fake_fetch_and_parse_sitemap):
            result = discover_candidates_from_plans(
                plans,
                registry=registry,
                max_sitemaps_per_domain=10,
                topk=5,
                min_score=0,
                timeout_seconds=1.0,
                max_bytes=1024,
                max_redirects=1,
            )

        self.assertGreaterEqual(len(result.candidates), 1)
        self.assertEqual(result.candidates[0].plan_index, 0)
        self.assertEqual(result.default_entrypoints_used_count, 1)
        self.assertEqual(result.seeds_used_count, 1)

        report = result.plan_reports[0]
        self.assertEqual(report.plan_index, 0)
        self.assertTrue(report.registry_used)
        self.assertTrue(report.default_used)
        self.assertGreaterEqual(report.parsed_indexes, 1)
        self.assertGreaterEqual(report.parsed_urlsets, 1)
        self.assertGreaterEqual(report.candidates_emitted, 1)
        self.assertTrue(any(item.get("url") == "https://example.com/custom-seed.xml" for item in report.entrypoints_tried))
        self.assertTrue(any(item.get("url") == "https://example.com/sitemap_index.xml" for item in report.entrypoints_tried))
        self.assertTrue(any(err.get("reason") == "http_status" for err in report.errors))

    def test_robots_fallback_adds_sitemap_when_default_entrypoints_fail(self) -> None:
        plans = [
            {
                "retail_url": "https://example.invalid/psu/2",
                "source": "coolpc",
                "category": "PSU",
                "title": "Seasonic FOCUS GX-850",
                "sku_hint": "FOCUS GX-850",
                "brand_key": "seasonic",
                "brand_source": "title_or_sku_hint+registry_alias",
                "brand_raw": "seasonic",
                "allowed_domains": ["example.com"],
                "query_terms": ["FOCUS GX-850"],
                "decision": "ok",
                "decision_notes": "ok",
            }
        ]
        registry = OfficialRegistry(
            version=1,
            brands=[
                BrandRegistryEntry(
                    brand_key="seasonic",
                    brand_aliases=["Seasonic"],
                    allowed_domains=["example.com"],
                    sitemap_urls=[],
                )
            ],
            alias_map={"SEASONIC": "seasonic"},
        )

        def fake_fetch_and_parse_sitemap(
            *,
            client,
            sitemap_url: str,
            allowed_hosts: set[str],
            timeout_seconds: float,
            max_bytes: int,
            max_redirects: int,
        ) -> tuple[str, list[str], int]:
            if sitemap_url == "https://example.com/sitemap-products.xml":
                return (
                    "urlset",
                    [
                        "https://example.com/products/focus-gx-850-a",
                        "https://example.com/products/focus-gx-850-b",
                    ],
                    1,
                )
            raise discover_mod._SitemapFetchError("http_status", "404", request_count=1)

        def fake_fetch_robots_txt(
            *,
            client,
            robots_url: str,
            allowed_hosts: set[str],
            timeout_seconds: float,
            max_bytes: int,
            max_redirects: int,
        ) -> tuple[str, int]:
            self.assertEqual(robots_url, "https://example.com/robots.txt")
            return ("User-agent: *\nSitemap: https://example.com/sitemap-products.xml\n", 1)

        with mock.patch.object(discover_mod, "_build_fetch_client", return_value=object()), mock.patch.object(
            discover_mod, "_close_fetch_client", return_value=None
        ), mock.patch.object(discover_mod, "_fetch_and_parse_sitemap", side_effect=fake_fetch_and_parse_sitemap), mock.patch.object(
            discover_mod, "_fetch_robots_txt", side_effect=fake_fetch_robots_txt
        ):
            result = discover_candidates_from_plans(
                plans,
                registry=registry,
                max_sitemaps_per_domain=10,
                topk=5,
                min_score=0,
                timeout_seconds=1.0,
                max_bytes=1024,
                max_redirects=1,
            )

        self.assertGreaterEqual(len(result.candidates), 2)
        self.assertNotIn("no_sitemap_found", result.error_reasons)
        report = result.plan_reports[0]
        self.assertTrue(any(item.get("source") == "robots" and item.get("status") == "ok" for item in report.entrypoints_tried))
        self.assertTrue(any(item.get("url") == "https://example.com/sitemap-products.xml" for item in report.entrypoints_tried))

    def test_parse_robots_sitemaps_stable_unique(self) -> None:
        text = (
            "User-agent: *\n"
            "Sitemap: https://example.com/a.xml\n"
            "sitemap :   https://example.com/b.xml \n"
            "SITEMAP:https://example.com/a.xml\n"
        )
        self.assertEqual(
            parse_robots_sitemaps(text),
            ["https://example.com/a.xml", "https://example.com/b.xml"],
        )

    def test_plan_quarantined_when_sitemap_returns_403(self) -> None:
        plans = [
            {
                "retail_url": "https://example.invalid/psu/403",
                "source": "coolpc",
                "category": "PSU",
                "title": "MSI MPG A1000G",
                "sku_hint": "MPG A1000G",
                "brand_key": "msi",
                "brand_source": "title_or_sku_hint+registry_alias",
                "brand_raw": "msi",
                "allowed_domains": ["example.com"],
                "query_terms": ["MPG A1000G"],
                "decision": "ok",
                "decision_notes": "ok",
            }
        ]
        registry = OfficialRegistry(
            version=1,
            brands=[
                BrandRegistryEntry(
                    brand_key="msi",
                    brand_aliases=["MSI"],
                    allowed_domains=["example.com"],
                    sitemap_urls=[],
                )
            ],
            alias_map={"MSI": "msi"},
        )
        attempted_urls: list[str] = []

        def fake_fetch_and_parse_sitemap(
            *,
            client,
            sitemap_url: str,
            allowed_hosts: set[str],
            timeout_seconds: float,
            max_bytes: int,
            max_redirects: int,
        ) -> tuple[str, list[str], int]:
            attempted_urls.append(sitemap_url)
            raise discover_mod._SitemapFetchError("http_status", "403", request_count=1)

        with mock.patch.object(discover_mod, "_build_fetch_client", return_value=object()), mock.patch.object(
            discover_mod, "_close_fetch_client", return_value=None
        ), mock.patch.object(discover_mod, "_fetch_and_parse_sitemap", side_effect=fake_fetch_and_parse_sitemap):
            result = discover_candidates_from_plans(
                plans,
                registry=registry,
                max_sitemaps_per_domain=10,
                topk=5,
                min_score=0,
                timeout_seconds=1.0,
                max_bytes=1024,
                max_redirects=1,
            )

        self.assertEqual(len(attempted_urls), 1)
        self.assertIn("blocked_http_status", result.error_reasons)
        self.assertNotIn("no_sitemap_found", result.error_reasons)
        report = result.plan_reports[0]
        self.assertEqual(report.decision, "quarantine")
        self.assertTrue(any(err.get("reason") == "blocked_http_status" for err in report.errors))

    def test_plan_quarantined_when_robots_returns_403(self) -> None:
        plans = [
            {
                "retail_url": "https://example.invalid/psu/robots403",
                "source": "coolpc",
                "category": "PSU",
                "title": "MSI MAG A850GL",
                "sku_hint": "MAG A850GL",
                "brand_key": "msi",
                "brand_source": "title_or_sku_hint+registry_alias",
                "brand_raw": "msi",
                "allowed_domains": ["example.com"],
                "query_terms": ["MAG A850GL"],
                "decision": "ok",
                "decision_notes": "ok",
            }
        ]
        registry = OfficialRegistry(
            version=1,
            brands=[
                BrandRegistryEntry(
                    brand_key="msi",
                    brand_aliases=["MSI"],
                    allowed_domains=["example.com"],
                    sitemap_urls=[],
                )
            ],
            alias_map={"MSI": "msi"},
        )

        def fake_fetch_robots_txt(
            *,
            client,
            robots_url: str,
            allowed_hosts: set[str],
            timeout_seconds: float,
            max_bytes: int,
            max_redirects: int,
        ) -> tuple[str, int]:
            raise discover_mod._SitemapFetchError("http_status", "403", request_count=1)

        with mock.patch.object(discover_mod, "_build_fetch_client", return_value=object()), mock.patch.object(
            discover_mod, "_close_fetch_client", return_value=None
        ), mock.patch.object(discover_mod, "_build_default_entry_urls", return_value=[]), mock.patch.object(
            discover_mod, "_fetch_and_parse_sitemap"
        ) as mock_fetch_sitemap, mock.patch.object(
            discover_mod, "_fetch_robots_txt", side_effect=fake_fetch_robots_txt
        ):
            result = discover_candidates_from_plans(
                plans,
                registry=registry,
                max_sitemaps_per_domain=10,
                topk=5,
                min_score=0,
                timeout_seconds=1.0,
                max_bytes=1024,
                max_redirects=1,
            )

        mock_fetch_sitemap.assert_not_called()
        self.assertIn("blocked_http_status", result.error_reasons)
        self.assertNotIn("no_sitemap_found", result.error_reasons)
        report = result.plan_reports[0]
        self.assertEqual(report.decision, "quarantine")
        self.assertTrue(any(err.get("reason") == "blocked_http_status" for err in report.errors))

    def test_sitemap_truncated_range_still_extracts_locs(self) -> None:
        payload = _build_large_urlset_bytes(min_size=discover_mod.SITEMAP_FETCH_MAX_BYTES + 4096)
        self.assertGreater(len(payload), discover_mod.SITEMAP_FETCH_MAX_BYTES)

        opener = _FakeUrlLibOpener(payload)
        with mock.patch.object(discover_mod, "httpx", None):
            kind, urls, request_count = discover_mod._fetch_and_parse_sitemap(
                client=opener,
                sitemap_url="https://example.com/sitemap.xml",
                allowed_hosts={"example.com"},
                timeout_seconds=1.0,
                max_bytes=131_072,
                max_redirects=0,
            )

        self.assertEqual(kind, "urlset")
        self.assertGreaterEqual(len(urls), 2)
        self.assertEqual(request_count, 1)

    def test_sitemap_still_too_large_over_new_cap(self) -> None:
        payload = _build_large_non_sitemap_bytes(min_size=discover_mod.SITEMAP_FETCH_MAX_BYTES + 1024)
        self.assertGreater(len(payload), discover_mod.SITEMAP_FETCH_MAX_BYTES)

        opener = _FakeUrlLibOpener(payload)
        with mock.patch.object(discover_mod, "httpx", None):
            with self.assertRaises(discover_mod._SitemapFetchError) as ctx:
                discover_mod._fetch_and_parse_sitemap(
                    client=opener,
                    sitemap_url="https://example.com/sitemap.xml",
                    allowed_hosts={"example.com"},
                    timeout_seconds=1.0,
                    max_bytes=131_072,
                    max_redirects=0,
                )
        self.assertEqual(ctx.exception.reason, "too_large")


if __name__ == "__main__":
    unittest.main()
