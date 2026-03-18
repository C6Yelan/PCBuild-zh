import unittest

from backend.services.crawler.link_consistency_gate.strategies.ram import RamStrategy
from backend.services.crawler.link_consistency_gate.types import ListingInput, PageSignals


class TestRamStrategy(unittest.TestCase):
    def test_match_cjk_brand_with_english_maker_hint(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="RAM",
            title="金士頓 單條16GB DDR5-5600(CL46) FURY Beast (獸獵者)",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="金士頓 單條16 GB DDR 5-5600/CL 46",
            extra={
                "maker_hint": "KINGSTON",
                "ddr_gen_hint": "DDR5",
                "speed_mts_hint": 5600,
                "capacity_gb_hint": 16,
                "kit_dimms_hint": 1,
                "cl_hint": 46,
            },
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="金士頓 單條16GB DDR5-5600/CL46",
        )

        decision = RamStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        for k in ("listing_tokens", "page_tokens", "matched_tokens", "notes"):
            self.assertIn(k, decision.evidence)
            self.assertIsInstance(decision.evidence[k], list)

    def test_match_phrase_hit_with_sku_hint(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="RAM",
            title="威剛 單條16GB D5-5600/CL46 LancerBlade矮 黑(AX5U5600C4616G-SLABBK)",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="AX5U5600C4616G-SLABBK",
            extra={
                "maker_hint": "ADATA",
                "ddr_gen_hint": "DDR5",
                "speed_mts_hint": 5600,
                "capacity_gb_hint": 16,
                "kit_dimms_hint": 1,
                "cl_hint": 46,
            },
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="ADATA AX5U5600C4616G-SLABBK DDR5 5600 16GB CL46",
        )

        decision = RamStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_PHRASE_FOUND")
        for k in ("listing_tokens", "page_tokens", "matched_tokens", "notes"):
            self.assertIn(k, decision.evidence)
            self.assertIsInstance(decision.evidence[k], list)

    def test_mismatch_when_no_identity_token_matches(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="RAM",
            title="威剛 單條16GB D5-5600/CL46 LancerBlade矮 黑(AX5U5600C4616G-SLABBK)",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="AX5U5600C4616G-SLABBK",
            extra={
                "maker_hint": "ADATA",
                "ddr_gen_hint": "DDR5",
                "speed_mts_hint": 5600,
                "capacity_gb_hint": 16,
                "kit_dimms_hint": 1,
                "cl_hint": 46,
            },
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="G.SKILL F5-6000J3636F16GX2-RS5K DDR5 6000 32GB CL36",
        )

        decision = RamStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "mismatch")
        self.assertEqual(decision.reason_code, "IDENTITY_TOKEN_MISSING")
        for k in ("listing_tokens", "page_tokens", "matched_tokens", "notes"):
            self.assertIn(k, decision.evidence)
            self.assertIsInstance(decision.evidence[k], list)

    def test_uncertain_when_page_text_empty(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="RAM",
            title="UMAX 單條16GB DDR5-4800/CL40",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="UMAX 單條16 GB DDR 5-4800/CL 40",
            extra={
                "maker_hint": "UMAX",
                "ddr_gen_hint": "DDR5",
                "speed_mts_hint": 4800,
                "capacity_gb_hint": 16,
                "kit_dimms_hint": 1,
                "cl_hint": 40,
            },
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint=None,
        )

        decision = RamStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "uncertain")
        self.assertEqual(decision.reason_code, "PAGE_TEXT_EMPTY")
        for k in ("listing_tokens", "page_tokens", "matched_tokens", "notes"):
            self.assertIn(k, decision.evidence)
            self.assertIsInstance(decision.evidence[k], list)


if __name__ == "__main__":
    unittest.main()
