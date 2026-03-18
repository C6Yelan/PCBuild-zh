import unittest

from backend.services.crawler.link_consistency_gate.strategies.case import CaseStrategy
from backend.services.crawler.link_consistency_gate.types import ListingInput, PageSignals


class TestCaseStrategy(unittest.TestCase):
    def _assert_evidence_shape(self, evidence: dict) -> None:
        for k in ("listing_tokens", "page_tokens", "matched_tokens", "notes"):
            self.assertIn(k, evidence)
            self.assertIsInstance(evidence[k], list)
            self.assertTrue(all(isinstance(v, str) for v in evidence[k]))

    def test_phrase_match_model_phrase_found(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="CASE",
            title="Montech AIR 903 MAX 黑/玻璃側透",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="",
            extra={"model_hint": "Montech AIR 903 MAX 黑"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="MONTECH AIR 903 MAX 中塔機殼 (ARGB)",
        )

        decision = CaseStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_PHRASE_FOUND")
        self._assert_evidence_shape(decision.evidence)

    def test_token_fallback_match_model_token_match(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="CASE",
            title="Corsair 4000D Airflow 黑",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="",
            extra={"model_hint": "Corsair 4000D Airflow 黑"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="CORSAIR 4000D RGB AIRFLOW Tempered Glass Case",
        )

        decision = CaseStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_TOKEN_MATCH")
        self._assert_evidence_shape(decision.evidence)

    def test_mismatch_identity_token_missing(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="CASE",
            title="DEEPCOOL MATREXX55 MESH",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="",
            extra={"model_hint": "DEEPCOOL MATREXX55 MESH"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="MONTECH AIR 903 MAX CASE",
        )

        decision = CaseStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "mismatch")
        self.assertEqual(decision.reason_code, "IDENTITY_TOKEN_MISSING")
        self._assert_evidence_shape(decision.evidence)

    def test_uncertain_when_page_text_empty(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="CASE",
            title="Montech AIR 903 MAX 黑",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="AIR903MAX",
            extra={"model_hint": "Montech AIR 903 MAX 黑"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title="",
            page_h1="",
            canonical_url=None,
            text_hint="",
        )

        decision = CaseStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "uncertain")
        self.assertEqual(decision.reason_code, "PAGE_TEXT_EMPTY")
        self._assert_evidence_shape(decision.evidence)


if __name__ == "__main__":
    unittest.main()
