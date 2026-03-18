import unittest

from backend.services.crawler.link_consistency_gate.strategies.hdd import HddStrategy
from backend.services.crawler.link_consistency_gate.types import ListingInput, PageSignals


class TestHddStrategy(unittest.TestCase):
    def _assert_evidence_shape(self, evidence: dict) -> None:
        for k in ("listing_tokens", "page_tokens", "matched_tokens", "notes"):
            self.assertIn(k, evidence)
            self.assertIsInstance(evidence[k], list)

    def test_match_canonical_phrase_with_inserted_space(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="HDD",
            title="Toshiba 2TB (HDW D320UZSVA)",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="HDWD320UZSVA",
            extra={"model_hint": "HDWD320UZSVA"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="TOSHIBA P300 2TB HDD HDW D320UZSVA",
        )

        decision = HddStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_PHRASE_FOUND")
        self._assert_evidence_shape(decision.evidence)

    def test_match_token_fallback_identity_overlap(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="HDD",
            title="Seagate Barracuda 2TB (DM008S)",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="DM008S",
            extra={"model_hint": "ST2000DM008"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="SEAGATE BARRACUDA 2TB DM008S",
        )

        decision = HddStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_TOKEN_MATCH")
        self._assert_evidence_shape(decision.evidence)

    def test_mismatch_identity_missing(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="HDD",
            title="WD 8TB (WD80EAAZ)",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="WD80EAAZ",
            extra={"model_hint": "WD80EAAZ"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="Seagate Barracuda ST2000DM008 2TB 7200RPM",
        )

        decision = HddStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "mismatch")
        self.assertEqual(decision.reason_code, "IDENTITY_TOKEN_MISSING")
        self._assert_evidence_shape(decision.evidence)

    def test_uncertain_when_page_text_empty(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="HDD",
            title="WD 8TB (WD80EAAZ)",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="WD80EAAZ",
            extra={"model_hint": "WD80EAAZ"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title="",
            page_h1="",
            canonical_url=None,
            text_hint="",
        )

        decision = HddStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "uncertain")
        self.assertEqual(decision.reason_code, "PAGE_TEXT_EMPTY")
        self._assert_evidence_shape(decision.evidence)


if __name__ == "__main__":
    unittest.main()

