from __future__ import annotations

import unittest

from backend.services.crawler.official_reconcile_gate.discovery.discover import score_candidate_urls
from backend.services.crawler.official_reconcile_gate.discovery.sitemap import SitemapParseError, parse_sitemap


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


if __name__ == "__main__":
    unittest.main()
