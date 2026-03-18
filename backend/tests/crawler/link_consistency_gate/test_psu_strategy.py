import unittest

from backend.services.crawler.link_consistency_gate.strategies.psu import PsuStrategy
from backend.services.crawler.link_consistency_gate.types import ListingInput, PageSignals


class TestPsuStrategy(unittest.TestCase):
    def _assert_evidence_shape(self, evidence: dict) -> None:
        for k in ("listing_tokens", "page_tokens", "matched_tokens", "notes"):
            self.assertIn(k, evidence)
            self.assertIsInstance(evidence[k], list)
            self.assertTrue(all(isinstance(v, str) for v in evidence[k]))

    def test_phrase_match_with_cjk_brand_prefix(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="POWER",
            title="微星 MAG A650GLS 650W 金牌",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="",
            extra={"model_hint": "微星 MAG A650GLS 650W"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="MSI MAG A650GLS 650W 80PLUS GOLD",
        )

        decision = PsuStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_PHRASE_FOUND")
        self._assert_evidence_shape(decision.evidence)

    def test_token_fallback_match(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="POWER",
            title="Corsair SHIFT RM850X 模組化電源",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="",
            extra={"model_hint": "Corsair SHIFT RM850X"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="CORSAIR RM850X 850W FULL MODULAR",
        )

        decision = PsuStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_TOKEN_MATCH")
        self._assert_evidence_shape(decision.evidence)

    def test_mismatch_identity_token_missing(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="POWER",
            title="MSI MAG A650GLS 650W",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="",
            extra={"model_hint": "MSI MAG A650GLS 650W"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="CORSAIR SF750 750W SFX PSU",
        )

        decision = PsuStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "mismatch")
        self.assertEqual(decision.reason_code, "IDENTITY_TOKEN_MISSING")
        self._assert_evidence_shape(decision.evidence)

    def test_uncertain_when_page_text_empty(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="POWER",
            title="Seasonic Focus GX-750",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="GX-750",
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

        decision = PsuStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "uncertain")
        self.assertEqual(decision.reason_code, "PAGE_TEXT_EMPTY")
        self._assert_evidence_shape(decision.evidence)

    def test_match_when_sku_hint_is_only_wattage(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="PSU",
            title="酷碼 X Silent Max Platinum 1300W /白金/全模組/數位靜音電源/ATX3.1(PCIe 5.0)/15年",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="1300W",
            extra={},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="X Silent Max Platinum 1300W ATX3.1 PCIe 5.0 全模組",
        )

        decision = PsuStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertIn(decision.reason_code, {"MODEL_PHRASE_FOUND", "MODEL_TOKEN_MATCH"})
        self._assert_evidence_shape(decision.evidence)
        self.assertIn("ignored_weak_sku_hint", decision.evidence["notes"])

    def test_phrase_match_when_sku_hint_missing_intermediate_token(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="PSU",
            title="酷碼 X Silent Max Platinum 1300W /白金/全模組/數位靜音電源/ATX3.1(PCIe 5.0)/15年",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="酷碼 X Silent Max 1300W",
            extra={},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="X Silent Max Platinum 1300W ATX3.1 PCIe 5.0 全模組",
        )

        decision = PsuStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_PHRASE_FOUND")
        self._assert_evidence_shape(decision.evidence)
        self.assertIn("model_source=sku_hint", decision.evidence["notes"])
        self.assertIn("added_title_head_candidates", decision.evidence["notes"])
        self.assertIn("phrase_match", decision.evidence["notes"])
        self.assertTrue(any(n.startswith("candidate_used=") for n in decision.evidence["notes"]))

    def test_match_when_lowercase_wattage_sku_hint_should_not_use_sku_source(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="PSU",
            title="酷碼 X Silent Max Platinum 1300W /白金/全模組/數位靜音電源/ATX3.1(PCIe 5.0)/15年",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="1300w",
            extra={},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="X Silent MAX Platinum 1300W ATX 3.1 PCIe 5.0 fully modular",
        )

        decision = PsuStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertIn(decision.reason_code, {"MODEL_PHRASE_FOUND", "MODEL_TOKEN_MATCH"})
        self._assert_evidence_shape(decision.evidence)
        self.assertIn("ignored_weak_sku_hint", decision.evidence["notes"])
        model_source_notes = [n for n in decision.evidence["notes"] if n.startswith("model_source=")]
        self.assertTrue(model_source_notes)
        self.assertNotIn("model_source=sku_hint", model_source_notes)
        self.assertGreater(len(decision.evidence["listing_tokens"]), 1)
        self.assertNotEqual(decision.evidence["listing_tokens"], ["1300W"])


if __name__ == "__main__":
    unittest.main()
