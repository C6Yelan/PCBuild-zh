from __future__ import annotations

import unittest

from backend.services.crawler.official_reconcile_gate.discovery.url_normalize import normalize_official_url


class TestUrlNormalize(unittest.TestCase):
    def test_globalarticles_rewritten_to_articles(self) -> None:
        url = "https://rog.asus.com/globalarticles/psus/foo/?a=1#x"
        expected = "https://rog.asus.com/articles/psus/foo/?a=1#x"
        self.assertEqual(normalize_official_url(url), expected)

    def test_globaltag_rewritten_to_tag_with_trailing_slash(self) -> None:
        url = "https://rog.asus.com/globaltag/rog-loki"
        expected = "https://rog.asus.com/tag/rog-loki/"
        self.assertEqual(normalize_official_url(url), expected)

    def test_non_rog_domain_unchanged(self) -> None:
        url = "https://www.asus.com/globalarticles/psus/foo/"
        self.assertEqual(normalize_official_url(url), url)

    def test_normalize_is_idempotent(self) -> None:
        url = "https://rog.asus.com/globaltag/rog-loki?x=1"
        normalized = normalize_official_url(url)
        self.assertEqual(normalize_official_url(normalized), normalized)


if __name__ == "__main__":
    unittest.main()
