# backend/services/crawler/link_consistency_gate/tests/test_cpu_strategy.py
import unittest

from backend.services.crawler.link_consistency_gate.strategies.cpu import CpuStrategy
from backend.services.crawler.link_consistency_gate.types import ListingInput, PageSignals


class TestCpuStrategy(unittest.TestCase):
    def test_match_i5_14400f_phrase_found_in_title(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="CPU",
            title="Intel Core i5-14400F【10核】",
            url="https://example.invalid/evaluate.php?iBuy=123",
            sku_hint="i5-14400F",
            extra={"brand_hint": "Intel", "model_hint": "i5-14400F"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title="Intel Core i5-14400F Processor",
            page_h1=None,
            canonical_url=None,
            text_hint=None,
        )

        decision = CpuStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_PHRASE_FOUND")

    def test_mismatch_i5_14400f_vs_i5_14400_missing_suffix(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="CPU",
            title="Intel Core i5-14400F【10核】",
            url="https://example.invalid/evaluate.php?iBuy=123",
            sku_hint="i5-14400F",
            extra={"brand_hint": "Intel", "model_hint": "i5-14400F"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title="Intel Core i5-14400 Processor",
            page_h1=None,
            canonical_url=None,
            text_hint=None,
        )

        decision = CpuStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "mismatch")
        self.assertEqual(decision.reason_code, "MODEL_TOKEN_MISSING")

    def test_uncertain_when_page_text_empty(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="CPU",
            title="Intel Core i5-14400F【10核】",
            url="https://example.invalid/evaluate.php?iBuy=123",
            sku_hint="i5-14400F",
            extra={"brand_hint": "Intel", "model_hint": "i5-14400F"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint=None,
        )

        decision = CpuStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "uncertain")
        self.assertEqual(decision.reason_code, "PAGE_TEXT_EMPTY")


if __name__ == "__main__":
    unittest.main()

