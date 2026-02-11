import unittest

from backend.services.crawler.link_consistency_gate.strategies.cooler import CoolerStrategy
from backend.services.crawler.link_consistency_gate.types import ListingInput, PageSignals


class TestCoolerStrategy(unittest.TestCase):
    def _assert_evidence_shape(self, evidence: dict) -> None:
        for k in ("listing_tokens", "page_tokens", "matched_tokens", "notes"):
            self.assertIn(k, evidence)
            self.assertIsInstance(evidence[k], list)

    def test_phrase_match_model_phrase_found(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="COOLER",
            title="Montech NX600 ARGB 黑 6導管/高16",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="Montech NX600 ARGB 黑 6導管",
            extra={"model_hint": "Montech NX600 ARGB 黑 6導管"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="Montech NX600 ARGB 黑 6導管 雙塔雙扇 散熱器",
        )

        decision = CoolerStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_PHRASE_FOUND")
        self._assert_evidence_shape(decision.evidence)

    def test_token_fallback_match_model_token_match(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="COOLER",
            title="ID-COOLING SE-214-XT BASIC 散熱器",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="ID-COOLING SE-214-XT BASIC",
            extra={"model_hint": "ID-COOLING SE-214-XT BASIC"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="SE 214 XT BASIC tower air cooler",
        )

        decision = CoolerStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_TOKEN_MATCH")
        self._assert_evidence_shape(decision.evidence)

    def test_mismatch_model_token_missing(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="COOLER",
            title="Montech NX600 ARGB 黑 6導管/高16",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="Montech NX600 ARGB 黑 6導管",
            extra={"model_hint": "NX600"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="Montech NX400 ARGB 黑 4導管",
        )

        decision = CoolerStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "mismatch")
        self.assertEqual(decision.reason_code, "MODEL_TOKEN_MISSING")
        self._assert_evidence_shape(decision.evidence)

    def test_uncertain_when_page_text_empty(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="COOLER",
            title="ID-COOLING SE-214-XT BASIC 散熱器",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="ID-COOLING SE-214-XT BASIC",
            extra={"model_hint": "ID-COOLING SE-214-XT BASIC"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title="",
            page_h1="",
            canonical_url=None,
            text_hint="",
        )

        decision = CoolerStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "uncertain")
        self.assertEqual(decision.reason_code, "PAGE_TEXT_EMPTY")
        self._assert_evidence_shape(decision.evidence)


if __name__ == "__main__":
    unittest.main()

