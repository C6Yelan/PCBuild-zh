import unittest

from backend.services.crawler.link_consistency_gate.strategies.mb import MbStrategy
from backend.services.crawler.link_consistency_gate.types import ListingInput, PageSignals


class TestMbStrategy(unittest.TestCase):
    def test_match_phrase_h610m_itx_edp(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="MB",
            title="ASRock H610M-ITX/eDP",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="H610M-ITX/eDP",
            extra={"model_hint": "H610M-ITX/eDP"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title="ASROCK h610m itx edp motherboard",
            page_h1=None,
            canonical_url=None,
            text_hint=None,
        )

        decision = MbStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_PHRASE_FOUND")
        for k in ("listing_tokens", "page_tokens", "matched_tokens", "notes"):
            self.assertIn(k, decision.evidence)
            self.assertIsInstance(decision.evidence[k], list)

    def test_mismatch_h610m_itx_edp_vs_h610m_h2_m2(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="MB",
            title="ASRock H610M-ITX/eDP",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="H610M-ITX/eDP",
            extra={"model_hint": "H610M-ITX/eDP"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title="ASRock H610M-H2/M.2",
            page_h1=None,
            canonical_url=None,
            text_hint=None,
        )

        decision = MbStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "mismatch")
        self.assertEqual(decision.reason_code, "MODEL_TOKEN_MISSING")
        for k in ("listing_tokens", "page_tokens", "matched_tokens", "notes"):
            self.assertIn(k, decision.evidence)

    def test_uncertain_when_page_text_empty(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="MB",
            title="ASRock H610M-ITX/eDP",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="H610M-ITX/eDP",
            extra={"model_hint": "H610M-ITX/eDP"},
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint=None,
        )

        decision = MbStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "uncertain")
        self.assertEqual(decision.reason_code, "PAGE_TEXT_EMPTY")
        for k in ("listing_tokens", "page_tokens", "matched_tokens", "notes"):
            self.assertIn(k, decision.evidence)


if __name__ == "__main__":
    unittest.main()

