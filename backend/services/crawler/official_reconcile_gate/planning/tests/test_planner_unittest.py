# backend/services/crawler/official_reconcile_gate/planning/tests/test_planner_unittest.py
from __future__ import annotations

import unittest
from pathlib import Path

from backend.services.crawler.official_reconcile_gate.planning.planner import build_official_lookup_plan
from backend.services.crawler.official_reconcile_gate.planning.registry import load_official_registry


class TestT6PlannerPhaseA(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        registry_path = Path(__file__).resolve().parents[1] / "data" / "official_registry.v1.json"
        cls.registry = load_official_registry(registry_path)

    def test_brand_from_extra_brand_hint(self) -> None:
        row = {
            "source": "coolpc",
            "category": "PSU",
            "title": "微星 MAG A650GLS 650W 金牌",
            "url": "https://example.invalid/item/msi-psu",
            "sku_hint": "MAG A650GLS",
            "extra": {
                "brand_hint": "MSI",
            },
        }

        plan = build_official_lookup_plan(row, self.registry)
        self.assertEqual(plan.brand_source, "extra.brand_hint")
        self.assertEqual(plan.brand_key, "msi")
        self.assertEqual(plan.brand_raw, "MSI")

    def test_brand_from_title_registry_alias(self) -> None:
        row = {
            "source": "coolpc",
            "category": "PSU",
            "title": "海韻 FOCUS GX-750 金牌全模組",
            "url": "https://example.invalid/item/seasonic-psu",
            "sku_hint": "FOCUS GX-750",
            "extra": {},
        }

        plan = build_official_lookup_plan(row, self.registry)
        self.assertEqual(plan.brand_key, "seasonic")
        self.assertEqual(plan.brand_source, "title_or_sku_hint+registry_alias")
        self.assertEqual(plan.brand_raw, "海韻")

    def test_quarantine_when_brand_unresolved(self) -> None:
        row = {
            "source": "coolpc",
            "category": "CASE_FAN",
            "title": "120mm ARGB PWM 風扇 三入組",
            "url": "https://example.invalid/item/case-fan",
            "sku_hint": "",
            "extra": {},
        }

        plan = build_official_lookup_plan(row, self.registry)
        self.assertIsNone(plan.brand_key)
        self.assertEqual(plan.brand_source, "unknown")
        self.assertEqual(plan.decision, "quarantine")


if __name__ == "__main__":
    unittest.main()
