import unittest

from backend.services.crawler.link_consistency_gate.strategies.expansion_card import ExpansionCardStrategy
from backend.services.crawler.link_consistency_gate.types import ListingInput, PageSignals


class TestExpansionCardStrategy(unittest.TestCase):
    def _assert_evidence_shape(self, evidence: dict) -> None:
        for k in ("listing_tokens", "page_tokens", "matched_tokens", "notes"):
            self.assertIn(k, evidence)
            self.assertIsInstance(evidence[k], list)
            self.assertTrue(all(isinstance(v, str) for v in evidence[k]))

    def test_phrase_match_model_phrase_found(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="EXPANSION_CARD",
            title="華碩 USB4 Card",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="",
            extra={"model_hint": "華碩 USB4 Card"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="USB4 PCIe Gen4 Card，這款 USB4 Card 可擴充",
        )

        decision = ExpansionCardStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_PHRASE_FOUND")
        self._assert_evidence_shape(decision.evidence)

    def test_token_fallback_match_model_token_match(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="EXPANSION_CARD",
            title="伽利略 M2PE42",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="",
            extra={"model_hint": "伽利略 M2PE42"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="這是 M2PE42 的產品頁",
        )

        decision = ExpansionCardStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_TOKEN_MATCH")
        self._assert_evidence_shape(decision.evidence)
        self.assertIn("M2PE42", decision.evidence["matched_tokens"])

    def test_mismatch_identity_token_missing(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="EXPANSION_CARD",
            title="伽利略 M2PE42",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="",
            extra={"model_hint": "伽利略 M2PE42"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="M2PE41",
        )

        decision = ExpansionCardStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "mismatch")
        self.assertEqual(decision.reason_code, "IDENTITY_TOKEN_MISSING")
        self._assert_evidence_shape(decision.evidence)

    def test_uncertain_when_page_text_empty(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="EXPANSION_CARD",
            title="華碩 USB4 Card",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="",
            extra={"model_hint": "華碩 USB4 Card"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title="",
            page_h1="",
            canonical_url=None,
            text_hint="",
        )

        decision = ExpansionCardStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "uncertain")
        self.assertEqual(decision.reason_code, "PAGE_TEXT_EMPTY")
        self._assert_evidence_shape(decision.evidence)

    def test_phrase_match_with_added_title_head_candidates(self) -> None:
        cases = [
            {
                "name": "model_hint_missing_x16",
                "title": "ASUS HYPER M.2 X16 GEN 4 CARD",
                "model_hint": "HYPER M2 GEN4 CARD",
                "text_hint": "Hyper M.2 x16 Gen4 Card",
            },
            {
                "name": "model_hint_too_short_usb4",
                "title": "ASUS USB4 PCIe Gen4 Card",
                "model_hint": "USB4 Card",
                "text_hint": "USB4 PCIe Gen4 Card",
            },
        ]

        for case in cases:
            with self.subTest(case=case["name"]):
                listing = ListingInput(
                    source="coolpc",
                    category="EXPANSION_CARD",
                    title=case["title"],
                    url="https://example.invalid/evaluate.php?iBuy=...",
                    sku_hint="",
                    extra={"model_hint": case["model_hint"]},
                )
                signals = PageSignals(
                    final_url="https://example.invalid/item",
                    http_status=200,
                    page_title=None,
                    page_h1=None,
                    canonical_url=None,
                    text_hint=case["text_hint"],
                )

                decision = ExpansionCardStrategy().decide(listing, signals)
                self.assertEqual(decision.status, "match")
                self.assertEqual(decision.reason_code, "MODEL_PHRASE_FOUND")
                self._assert_evidence_shape(decision.evidence)
                self.assertIn("added_title_head_candidates", decision.evidence["notes"])
                self.assertIn("phrase_source=title_head", decision.evidence["notes"])


if __name__ == "__main__":
    unittest.main()
