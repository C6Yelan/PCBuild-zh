import unittest

from backend.services.crawler.link_consistency_gate.strategies.case_fan import CaseFanStrategy
from backend.services.crawler.link_consistency_gate.types import ListingInput, PageSignals


class TestCaseFanStrategy(unittest.TestCase):
    def _assert_evidence_shape(self, evidence: dict) -> None:
        for k in ("listing_tokens", "page_tokens", "matched_tokens", "notes"):
            self.assertIn(k, evidence)
            self.assertIsInstance(evidence[k], list)
            self.assertTrue(all(isinstance(v, str) for v in evidence[k]))

    def test_phrase_match_model_phrase_found(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="CASE_FAN",
            title="Noctua NF-A12x25 PWM 120mm 機殼風扇",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="",
            extra={"model_hint": "Noctua NF-A12x25 PWM"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="NOCTUA NF-A12X25 PWM premium fan",
        )

        decision = CaseFanStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_PHRASE_FOUND")
        self._assert_evidence_shape(decision.evidence)

    def test_token_fallback_match_model_token_match(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="CASE_FAN",
            title="Noctua NF-A12x25 PWM chromax.black.swap",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="",
            extra={"model_hint": "Noctua NF-A12x25 PWM chromax.black.swap"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="NF-A12X25 120MM PWM CASE FAN",
        )

        decision = CaseFanStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_TOKEN_MATCH")
        self._assert_evidence_shape(decision.evidence)

    def test_mismatch_identity_token_missing(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="CASE_FAN",
            title="ARCTIC P12 PWM PST",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="ARCTIC P12 PWM PST",
            extra={},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="Noctua NF-A12x25",
        )

        decision = CaseFanStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "mismatch")
        self.assertEqual(decision.reason_code, "IDENTITY_TOKEN_MISSING")
        self._assert_evidence_shape(decision.evidence)

    def test_uncertain_when_page_text_empty(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="CASE_FAN",
            title="ARCTIC P12 PWM PST",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="ARCTIC P12 PWM PST",
            extra={},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title="",
            page_h1="",
            canonical_url=None,
            text_hint="",
        )

        decision = CaseFanStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "uncertain")
        self.assertEqual(decision.reason_code, "PAGE_TEXT_EMPTY")
        self._assert_evidence_shape(decision.evidence)


if __name__ == "__main__":
    unittest.main()
