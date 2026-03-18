import unittest

from backend.services.crawler.link_consistency_gate.strategies.liquid_cooling import (
    LiquidCoolingStrategy,
)
from backend.services.crawler.link_consistency_gate.types import ListingInput, PageSignals


class TestLiquidCoolingStrategy(unittest.TestCase):
    def _assert_evidence_shape(self, evidence: dict) -> None:
        for k in ("listing_tokens", "page_tokens", "matched_tokens", "notes"):
            self.assertIn(k, evidence)
            self.assertIsInstance(evidence[k], list)

    def test_phrase_match_model_phrase_found(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="LIQUID_COOLING",
            title="DEEPCOOL LE360 V2 360水冷",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="DEEPCOOL LE360 V2 360水冷",
            extra={"model_hint": "DEEPCOOL LE360 V2 360水冷", "brand_hint": "DEEPCOOL"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="DEEPCOOL LE360 V2 360水冷 一體式水冷散熱器",
        )

        decision = LiquidCoolingStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_PHRASE_FOUND")
        self._assert_evidence_shape(decision.evidence)

    def test_token_fallback_match_model_token_match(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="LIQUID_COOLING",
            title="DeepCool LS520SE 240 水冷",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="",
            extra={"model_hint": "DeepCool LS520SE 240mm", "brand_hint": "DEEPCOOL"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="DEEPCOOL LS 520 SE 240 水冷 ARGB",
        )

        decision = LiquidCoolingStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_TOKEN_MATCH")
        self._assert_evidence_shape(decision.evidence)

    def test_identity_missing_mismatch(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="LIQUID_COOLING",
            title="~~~~",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="",
            extra={"model_hint": "~~~~", "brand_hint": "DEEPCOOL"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="DEEPCOOL LE360 V2 360 水冷",
        )

        decision = LiquidCoolingStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "mismatch")
        self.assertEqual(decision.reason_code, "IDENTITY_TOKEN_MISSING")
        self._assert_evidence_shape(decision.evidence)

    def test_uncertain_when_page_text_empty(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="LIQUID_COOLING",
            title="DEEPCOOL LE360 V2 360水冷",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="DEEPCOOL LE360 V2 360水冷",
            extra={"model_hint": "DEEPCOOL LE360 V2 360水冷", "brand_hint": "DEEPCOOL"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title="",
            page_h1="",
            canonical_url=None,
            text_hint="",
        )

        decision = LiquidCoolingStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "uncertain")
        self.assertEqual(decision.reason_code, "PAGE_TEXT_EMPTY")
        self._assert_evidence_shape(decision.evidence)


if __name__ == "__main__":
    unittest.main()

