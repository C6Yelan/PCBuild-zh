from __future__ import annotations

import unittest

from backend.services.crawler.official_reconcile_gate.robots import fetch as robots_fetch
from backend.services.crawler.official_reconcile_gate.robots.fetch import RobotsFetchLimits, fetch_robots_txt
from backend.services.crawler.official_reconcile_gate.robots.matcher import is_allowed
from backend.services.crawler.official_reconcile_gate.robots.parser import parse_robots_txt
from backend.services.crawler.official_reconcile_gate.robots.types import RobotsFetchResult, RobotsPolicy


class TestRobotsPolicy(unittest.TestCase):
    def test_user_agent_merge_and_star_fallback(self) -> None:
        policy = parse_robots_txt(
            """
            User-agent: PCBuildBot
            Disallow: /private
            User-agent: PCBuildBot
            Allow: /private/open

            User-agent: *
            Disallow: /tmp
            """
        )

        allowed_bot, matched_bot = is_allowed(policy, "PCBuildBot", "/private/open/guide")
        self.assertTrue(allowed_bot)
        self.assertIsNotNone(matched_bot)
        self.assertEqual(matched_bot["directive"], "allow")
        self.assertEqual(matched_bot["pattern"], "/private/open")

        allowed_other, matched_other = is_allowed(policy, "OtherCrawler", "/tmp/file")
        self.assertFalse(allowed_other)
        self.assertIsNotNone(matched_other)
        self.assertEqual(matched_other["directive"], "disallow")
        self.assertEqual(matched_other["pattern"], "/tmp")

    def test_longest_match_and_equal_length_allow_wins(self) -> None:
        policy = parse_robots_txt(
            """
            User-agent: *
            Disallow: /abc
            Allow: /abc
            Disallow: /abc/secret
            Allow: /abc/secret/open
            """
        )

        allowed_equal, matched_equal = is_allowed(policy, "PCBuildBot", "/abc")
        self.assertTrue(allowed_equal)
        self.assertIsNotNone(matched_equal)
        self.assertEqual(matched_equal["directive"], "allow")
        self.assertEqual(matched_equal["pattern"], "/abc")

        allowed_secret, matched_secret = is_allowed(policy, "PCBuildBot", "/abc/secret/data")
        self.assertFalse(allowed_secret)
        self.assertIsNotNone(matched_secret)
        self.assertEqual(matched_secret["pattern"], "/abc/secret")

        allowed_open, matched_open = is_allowed(policy, "PCBuildBot", "/abc/secret/open/doc")
        self.assertTrue(allowed_open)
        self.assertIsNotNone(matched_open)
        self.assertEqual(matched_open["pattern"], "/abc/secret/open")

    def test_unreachable_disallow_all_and_unavailable_allow_all(self) -> None:
        unreachable = RobotsFetchResult(
            status="unreachable",
            policy=RobotsPolicy.disallow_all("unreachable"),
            robots_url="https://example.com/robots.txt",
        )
        unavailable = RobotsFetchResult(
            status="unavailable",
            policy=RobotsPolicy.allow_all("unavailable_4xx"),
            robots_url="https://example.com/robots.txt",
        )

        allowed_unreachable, _ = is_allowed(unreachable.policy, "PCBuildBot", "/any")
        allowed_unavailable, _ = is_allowed(unavailable.policy, "PCBuildBot", "/any")
        self.assertFalse(allowed_unreachable)
        self.assertTrue(allowed_unavailable)

    def test_validate_host_allows_www_apex_equivalence(self) -> None:
        err_apex = robots_fetch._validate_request_url(
            "https://corsair.com/robots.txt",
            allowed_hosts={"www.corsair.com"},
        )
        err_www = robots_fetch._validate_request_url(
            "https://www.corsair.com/robots.txt",
            allowed_hosts={"corsair.com"},
        )
        self.assertIsNone(err_apex)
        self.assertIsNone(err_www)

    def test_redirect_limit_exceeded_is_unavailable(self) -> None:
        class _FakeResponse:
            status_code = 301
            headers = {"location": "/robots.txt?r=1"}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def iter_bytes(self):
                yield b""

        class _FakeClient:
            def stream(self, method, url):
                return _FakeResponse()

        result = fetch_robots_txt(
            "https://example.com/anything",
            _FakeClient(),
            RobotsFetchLimits(timeout_seconds=1.0, max_bytes=512000, max_redirects=1),
            allowed_hosts={"example.com"},
        )

        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.policy.mode, "allow_all")
        self.assertEqual(result.policy.note, "redirect_limit_exceeded")


if __name__ == "__main__":
    unittest.main()
