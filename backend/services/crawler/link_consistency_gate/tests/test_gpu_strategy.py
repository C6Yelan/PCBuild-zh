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

    def test_token_identity_match_for_legacy_and_special_naming(self) -> None:
        cases = [
            {
                "name": "n210_alias_to_gt210",
                "model_hint": "MSI N210-MD1G/D3",
                "page_text": "MSI GT 210 1GB DDR3 風扇版",
                "expect_identity": "GT210",
            },
            {
                "name": "gt710_legacy",
                "model_hint": "ASUS GT710-SL-2GD5-BRK-EVO",
                "page_text": "華碩 GeForce GT 710 2GB DDR5",
                "expect_identity": "GT710",
            },
            {
                "name": "gt730_legacy",
                "model_hint": "MSI N730-2GD3V3",
                "page_text": "微星 GT 730 2GD3V3 DDR3",
                "expect_identity": "GT730",
            },
            {
                "name": "radeon_r7_240",
                "model_hint": "PowerColor AXR7 240 2GBD5-HLEV2",
                "page_text": "撼訊 Radeon R7 240 2GB DDR5",
                "expect_identity": "R7240",
            },
            {
                "name": "radeon_ai_pro_r9700",
                "model_hint": "SAPPHIRE AI PRO R9700 32GB",
                "page_text": "藍寶石 Radeon AI PRO R 9700 32G",
                "expect_identity": "R9700",
            },
        ]

        for case in cases:
            with self.subTest(case=case["name"]):
                listing = ListingInput(
                    source="coolpc",
                    category="GPU",
                    title=case["model_hint"],
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
                    text_hint=case["page_text"],
                )

                decision = GpuStrategy().decide(listing, signals)
                self.assertEqual(decision.status, "match")
                self.assertEqual(decision.reason_code, "MODEL_TOKEN_MATCH")
                self._assert_evidence_shape(decision.evidence)
                self.assertIn(case["expect_identity"], decision.evidence["matched_tokens"])

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
