from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from backend.tools.crawler import t6_build_official_lookup_plan as phase_a_cli


class TestT6SkipPlansReport(unittest.TestCase):
    def test_skip_plans_report_generated_with_deterministic_order(self) -> None:
        temp_root = Path("temp")
        temp_root.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(dir=temp_root, prefix="t6_skip_report_") as tmpdir:
            run_dir = Path(tmpdir)
            input_path = run_dir / "input.json"
            output_path = run_dir / "plans.json"

            payload = [
                {
                    "source": "coolpc",
                    "category": "PSU",
                    "title": "海韻 FOCUS GX-750 750W 金牌 全模組",
                    "url": "https://example.invalid/psu/1",
                    "sku_hint": "FOCUS GX-750",
                    "extra": {},
                },
                {
                    "source": "coolpc",
                    "category": "MB",
                    "title": "MSI B650M MORTAR WIFI",
                    "url": "https://example.invalid/mb/1",
                    "sku_hint": "B650M MORTAR WIFI",
                    "extra": {"brand_hint": "MSI"},
                },
                {
                    "source": "coolpc",
                    "category": "MB",
                    "title": "MSI PRO B650-S WIFI",
                    "url": "https://example.invalid/mb/2",
                    "sku_hint": "PRO B650-S WIFI",
                    "extra": {"brand_hint": "MSI"},
                },
                {
                    "source": "coolpc",
                    "category": "SSD",
                    "title": "ZZZ_UNKNOWN_BRAND SSD 1TB",
                    "url": "https://example.invalid/ssd/1",
                    "sku_hint": "UNKNOWN-1TB",
                    "extra": {},
                },
            ]
            input_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

            exit_code = phase_a_cli.main(
                [
                    "--input",
                    str(input_path),
                    "--output",
                    str(output_path),
                ]
            )
            self.assertEqual(exit_code, 0)

            report_path = run_dir / "skip_plans_report.json"
            self.assertTrue(report_path.exists())

            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(set(report.keys()), {"summary", "items"})

            summary = report["summary"]
            self.assertEqual(summary["total_plans"], 4)
            self.assertEqual(summary["ok"], 1)
            self.assertEqual(summary["needs_registry"], 2)
            self.assertEqual(summary["quarantine"], 1)

            items = report["items"]
            self.assertEqual(len(items), 3)

            required_keys = {
                "plan_index",
                "decision",
                "brand_key",
                "category",
                "retail_title",
                "retail_url",
                "notes",
            }
            for item in items:
                self.assertEqual(set(item.keys()), required_keys)

            self.assertEqual([item["decision"] for item in items], ["needs_registry", "needs_registry", "quarantine"])
            self.assertEqual([item["plan_index"] for item in items], [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
