from __future__ import annotations

import unittest
from unittest import mock

from backend.services.crawler.official_reconcile_gate.discovery import discover as discover_mod
from backend.services.crawler.official_reconcile_gate.discovery.discover import discover_candidates_from_plans, score_candidate_urls
from backend.services.crawler.official_reconcile_gate.discovery.sitemap import SitemapParseError, parse_sitemap
from backend.services.crawler.official_reconcile_gate.planning.types import BrandRegistryEntry, OfficialRegistry


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


if __name__ == "__main__":
    unittest.main()
