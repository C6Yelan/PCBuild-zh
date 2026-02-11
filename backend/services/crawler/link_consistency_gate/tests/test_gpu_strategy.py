import unittest

from backend.services.crawler.link_consistency_gate.strategies.gpu import GpuStrategy
from backend.services.crawler.link_consistency_gate.types import ListingInput, PageSignals


class TestGpuStrategy(unittest.TestCase):
    def _assert_evidence_shape(self, evidence: dict) -> None:
        for k in ("listing_tokens", "page_tokens", "matched_tokens", "notes"):
            self.assertIn(k, evidence)
            self.assertIsInstance(evidence[k], list)
            self.assertTrue(all(isinstance(x, str) for x in evidence[k]))

    def test_phrase_match_model_phrase_found(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="GPU",
            title="MSI GeForce RTX 4070 Ti SUPER 16G",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="",
            extra={"model_hint": "MSI GeForce RTX 4070 Ti SUPER 16G"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title="",
            page_h1="",
            canonical_url=None,
            text_hint="現貨 MSI GeForce RTX 4070 Ti SUPER 16G 顯示卡",
        )

        decision = GpuStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_PHRASE_FOUND")
        self._assert_evidence_shape(decision.evidence)

    def test_token_identity_match_with_glued_text(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="GPU",
            title="ASUS GeForce RTX 4060 Ti O8G",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="",
            extra={"model_hint": "ASUS GeForce RTX 4060 Ti O8G"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="華碩 GeForce RTX4060Ti 8GB GDDR6",
        )

        decision = GpuStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_TOKEN_MATCH")
        self._assert_evidence_shape(decision.evidence)

    def test_mismatch_when_suffix_differs(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="GPU",
            title="NVIDIA GeForce RTX 4060 8GB",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="",
            extra={"model_hint": "NVIDIA GeForce RTX 4060 8GB"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="NVIDIA GeForce RTX4060Ti 8GB GDDR6",
        )

        decision = GpuStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "mismatch")
        self.assertEqual(decision.reason_code, "MODEL_TOKEN_MISSING")
        self._assert_evidence_shape(decision.evidence)

    def test_uncertain_when_page_text_empty(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="GPU",
            title="GIGABYTE Radeon RX 7800 XT",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="RX7800XT",
            extra={"model_hint": "Radeon RX 7800 XT"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title="",
            page_h1="",
            canonical_url=None,
            text_hint="",
        )

        decision = GpuStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "uncertain")
        self.assertIn(decision.reason_code, {"PAGE_TEXT_EMPTY", "TOKEN_WEAK_OR_EMPTY"})
        self._assert_evidence_shape(decision.evidence)


if __name__ == "__main__":
    unittest.main()
