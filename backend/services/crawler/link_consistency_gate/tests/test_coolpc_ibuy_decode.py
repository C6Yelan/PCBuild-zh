# backend/services/crawler/link_consistency_gate/tests/test_coolpc_ibuy_decode.py
import base64
import sys
import types
import unittest

try: # 假的httpx模塊，用於在沒有安裝httpx的環境中運行單元測試，避免因缺少依賴而導致測試無法運行。
    import httpx  # noqa: F401
except ImportError:  # pragma: no cover
    # Keep unit tests runnable in minimal environments without optional deps.
    fake = types.ModuleType("httpx")

    class Timeout:  # minimal stub for engine init
        def __init__(self, *_args, **_kwargs) -> None:
            pass

    class Client:  # minimal stub for engine init/close
        def __init__(self, *args, **kwargs) -> None:
            pass

        def close(self) -> None:
            pass

    fake.Timeout = Timeout
    fake.Client = Client
    sys.modules["httpx"] = fake

from backend.services.crawler.link_consistency_gate.engine import LinkCheckEngine  # noqa: E402
from backend.services.crawler.link_consistency_gate import registry as registry_mod  # noqa: E402
from backend.services.crawler.link_consistency_gate.types import (  # noqa: E402
    BlockDetectionConfig,
    EngineConfig,
    FetchConfig,
    ListingInput,
    MatchDecision,
    PacingConfig,
)


class TestCoolpcIbuyDecode(unittest.TestCase):
    def test_raw_query_extraction_preserves_plus(self) -> None:
        class _CaptureStrategy:
            def __init__(self) -> None:
                self.signals = None

            def decide(self, listing, signals) -> MatchDecision:
                self.signals = signals
                return MatchDecision(
                    status="match",
                    score=None,
                    reason_code="CAPTURE",
                    evidence={"listing_tokens": [], "page_tokens": [], "matched_tokens": [], "notes": []},
                )

        strategy = _CaptureStrategy()
        prev = registry_mod.REGISTRY.get("TEST")
        registry_mod.REGISTRY["TEST"] = strategy
        try:
            url = "https://www.coolpc.com.tw/evaluate.php?foo=1&iBuy=ICA+&bar=2"
            listing = ListingInput(
                source="coolpc",
                category="TEST",
                title="",
                url=url,
                sku_hint="",
                extra={},
            )
            config = EngineConfig(
                fetch=FetchConfig(timeout_s=1.0, max_redirects=1, max_bytes=1024),
                pacing=PacingConfig(min_interval_ms=0, jitter_ms=0),
                block=BlockDetectionConfig(enabled=False, patterns=[]),
            )

            with LinkCheckEngine(config) as engine:
                def _fail_fetch(_url: str):
                    raise AssertionError("fetch() should not be called when iBuy decode succeeds")

                engine._fetcher.fetch = _fail_fetch  # type: ignore[method-assign]
                report = engine.check_one(listing)

            self.assertEqual(report.reason_code, "CAPTURE")
            self.assertIsNotNone(strategy.signals)
            self.assertEqual(strategy.signals.final_url, url)
            self.assertEqual(strategy.signals.http_status, 200)
            self.assertIsNone(strategy.signals.page_title)
            self.assertIsNone(strategy.signals.page_h1)
            self.assertIsNone(strategy.signals.canonical_url)
            self.assertEqual(strategy.signals.text_hint, "  >")
        finally:
            if prev is None:
                registry_mod.REGISTRY.pop("TEST", None)
            else:
                registry_mod.REGISTRY["TEST"] = prev

    def test_ibuy_decode_pads_base64(self) -> None:
        class _CaptureStrategy:
            def __init__(self) -> None:
                self.signals = None

            def decide(self, listing, signals) -> MatchDecision:
                self.signals = signals
                return MatchDecision(
                    status="match",
                    score=None,
                    reason_code="CAPTURE",
                    evidence={"listing_tokens": [], "page_tokens": [], "matched_tokens": [], "notes": []},
                )

        strategy = _CaptureStrategy()
        prev = registry_mod.REGISTRY.get("TEST")
        registry_mod.REGISTRY["TEST"] = strategy
        try:
            # "AB" -> "QUI="; remove padding to ensure we add it back.
            url = "https://www.coolpc.com.tw/evaluate.php?iBuy=QUI"
            listing = ListingInput(
                source="coolpc",
                category="TEST",
                title="",
                url=url,
                sku_hint="",
                extra={},
            )
            config = EngineConfig(
                fetch=FetchConfig(timeout_s=1.0, max_redirects=1, max_bytes=1024),
                pacing=PacingConfig(min_interval_ms=0, jitter_ms=0),
                block=BlockDetectionConfig(enabled=False, patterns=[]),
            )

            with LinkCheckEngine(config) as engine:
                def _fail_fetch(_url: str):
                    raise AssertionError("fetch() should not be called when iBuy decode succeeds")

                engine._fetcher.fetch = _fail_fetch  # type: ignore[method-assign]
                report = engine.check_one(listing)

            self.assertEqual(report.reason_code, "CAPTURE")
            self.assertIsNotNone(strategy.signals)
            self.assertEqual(strategy.signals.final_url, url)
            self.assertEqual(strategy.signals.http_status, 200)
            self.assertIsNone(strategy.signals.page_title)
            self.assertIsNone(strategy.signals.page_h1)
            self.assertIsNone(strategy.signals.canonical_url)
            self.assertEqual(strategy.signals.text_hint, "AB")
        finally:
            if prev is None:
                registry_mod.REGISTRY.pop("TEST", None)
            else:
                registry_mod.REGISTRY["TEST"] = prev

    def test_engine_skips_fetch_when_ibuy_decode_succeeds(self) -> None:
        text = "Intel Core i5-14400F"
        ibuy = base64.b64encode(text.encode("big5", errors="strict")).decode("ascii")
        url = f"https://www.coolpc.com.tw/evaluate.php?iBuy={ibuy}"

        listing = ListingInput(
            source="coolpc",
            category="CPU",
            title=text,
            url=url,
            sku_hint="i5-14400F",
            extra={"brand_hint": "Intel", "model_hint": "i5-14400F"},
        )

        config = EngineConfig(
            fetch=FetchConfig(timeout_s=1.0, max_redirects=1, max_bytes=1024),
            pacing=PacingConfig(min_interval_ms=0, jitter_ms=0),
            block=BlockDetectionConfig(enabled=False, patterns=[]),
        )

        with LinkCheckEngine(config) as engine:
            def _fail_fetch(_url: str):
                raise AssertionError("fetch() should not be called when iBuy decode succeeds")

            engine._fetcher.fetch = _fail_fetch  # type: ignore[method-assign]
            report = engine.check_one(listing)

        self.assertEqual(report.http_status, 200)
        self.assertEqual(report.final_url, url)
        self.assertNotEqual(report.status, "error")
        self.assertNotEqual(report.reason_code, "FETCH_ERROR")


if __name__ == "__main__":
    unittest.main()
