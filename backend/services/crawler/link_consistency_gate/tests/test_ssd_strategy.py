import unittest

from backend.services.crawler.link_consistency_gate.strategies.ssd import SsdStrategy
from backend.services.crawler.link_consistency_gate.types import ListingInput, PageSignals


class TestSsdStrategy(unittest.TestCase):
    def _assert_evidence_shape(self, evidence: dict) -> None:
        for k in ("listing_tokens", "page_tokens", "matched_tokens", "notes"):
            self.assertIn(k, evidence)
            self.assertIsInstance(evidence[k], list)

    def test_match_phrase_hit(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="SSD",
            title="WD Black SN850X 1TB/M.2 PCIe 4.0/NVMe/讀7300/寫6300",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="SN850X",
            extra={
                "brand_hint": "WD",
                "interface_hint": "PCIe",
                "protocol_hint": "NVMe",
                "form_factor_hint": "M.2",
            },
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="WD BLACK SN850X 1TB M.2 NVME PCIE 4.0",
        )

        decision = SsdStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_PHRASE_FOUND")
        self._assert_evidence_shape(decision.evidence)

    def test_match_phrase_hit_cjk_segment_without_english_brand_prefix(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="SSD",
            title="十銓 T-Force Vulcan Z 火神Z 256G/2.5吋/讀520/寫450/3D NAND/TLC",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="十銓 T-Force Vulcan Z 火神Z 256G/2.5吋/讀520/寫450/3D NAND/TLC",
            extra={
                "brand_hint": "TEAMGROUP",
                "interface_hint": "SATA",
                "protocol_hint": "AHCI",
                "form_factor_hint": '2.5"',
            },
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="十銓 T-Force Vulcan Z 火神Z 256G/2.5吋/讀520/寫450/3D NAND/TLC",
        )

        decision = SsdStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "match")
        self.assertEqual(decision.reason_code, "MODEL_PHRASE_FOUND")
        self._assert_evidence_shape(decision.evidence)

    def test_mismatch_identity_missing(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="SSD",
            title="威剛 Ultimate SU650 240G/2.5吋/讀520/寫450/TLC",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="SU650",
            extra={
                "brand_hint": "ADATA",
                "interface_hint": "SATA",
                "protocol_hint": "AHCI",
                "form_factor_hint": '2.5"',
            },
        )
        signals = PageSignals(
            final_url="https://example.invalid/item",
            http_status=200,
            page_title=None,
            page_h1=None,
            canonical_url=None,
            text_hint="KINGSTON A400 240GB 2.5 SATA AHCI",
        )

        decision = SsdStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "mismatch")
        self.assertEqual(decision.reason_code, "IDENTITY_TOKEN_MISSING")
        self._assert_evidence_shape(decision.evidence)

    def test_uncertain_when_page_text_empty(self) -> None:
        listing = ListingInput(
            source="coolpc",
            category="SSD",
            title="Crucial MX500 1TB/2.5吋/SATA/讀560/寫510",
            url="https://example.invalid/evaluate.php?iBuy=...",
            sku_hint="MX500",
            extra={
                "brand_hint": "CRUCIAL",
                "interface_hint": "SATA",
                "protocol_hint": "AHCI",
                "form_factor_hint": '2.5"',
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

        decision = SsdStrategy().decide(listing, signals)
        self.assertEqual(decision.status, "uncertain")
        self.assertEqual(decision.reason_code, "PAGE_TEXT_EMPTY")
        self._assert_evidence_shape(decision.evidence)


if __name__ == "__main__":
    unittest.main()
