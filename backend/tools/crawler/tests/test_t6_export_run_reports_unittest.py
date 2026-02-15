from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from backend.tools.crawler import t6_export_run_reports as export_cli


class TestT6ExportRunReports(unittest.TestCase):
    def test_export_reports_from_run_dir(self) -> None:
        temp_root = Path("temp")
        temp_root.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(dir=temp_root, prefix="t6_export_report_") as tmpdir:
            run_dir = Path(tmpdir)
            decisions_path = run_dir / "decisions.jsonl"
            skip_path = run_dir / "skip_plans_report.json"

            decision_rows = [
                {
                    "plan_index": 2,
                    "retail_title": "Accepted Row",
                    "retail_url": "https://example.invalid/accepted",
                    "decision": "accepted",
                    "decision_reason": "ok",
                    "matched_tokens": ["focus"],
                    "top_k_summary": [],
                },
                {
                    "plan_index": 1,
                    "retail_title": None,
                    "retail_url": "https://example.invalid/manual",
                    "decision": "needs_manual_review",
                    "decision_reason": "weak_match_only: matched_tokens=['rog'] top1_score=5 min_accept_score=3",
                    "matched_tokens": None,
                    "top_k_summary": [{"official_url": "https://example.invalid/o", "score": 5}],
                },
                {
                    "plan_index": 3,
                    "retail_title": "No Candidate Row",
                    "retail_url": "https://example.invalid/no-candidate",
                    "decision": "no_candidates",
                    "decision_reason": "no_candidates: no_sitemap_found",
                    "matched_tokens": [],
                    "top_k_summary": [],
                },
            ]
            with decisions_path.open("w", encoding="utf-8") as f:
                for row in decision_rows:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")

            skip_payload = {
                "summary": {"total_plans": 4, "ok": 1, "needs_registry": 2, "quarantine": 1},
                "items": [
                    {
                        "plan_index": 4,
                        "decision": "needs_registry",
                        "brand_key": None,
                        "category": "SSD",
                        "retail_title": "Unknown SSD",
                        "retail_url": "https://example.invalid/ssd",
                        "notes": "needs registry",
                    },
                    {
                        "plan_index": 5,
                        "decision": "needs_registry",
                        "brand_key": "asus",
                        "category": "MB",
                        "retail_title": "ASUS MB",
                        "retail_url": "https://example.invalid/mb",
                        "notes": "needs registry",
                    },
                    {
                        "plan_index": 6,
                        "decision": "quarantine",
                        "brand_key": None,
                        "category": "PSU",
                        "retail_title": "Unknown PSU",
                        "retail_url": "https://example.invalid/psu",
                        "notes": "quarantine",
                    },
                ],
            }
            skip_path.write_text(json.dumps(skip_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

            stderr = io.StringIO()
            with redirect_stderr(stderr):
                rc = export_cli.main(["--run-dir", str(run_dir)])
            self.assertEqual(rc, 0)
            self.assertIn("[T6] reports: needs_registry=2 quarantine=1 needs_manual_review=1", stderr.getvalue())

            registry_todo_path = run_dir / "registry_todo.json"
            quarantine_todo_path = run_dir / "quarantine_todo.json"
            manual_review_path = run_dir / "manual_review.jsonl"
            self.assertTrue(registry_todo_path.exists())
            self.assertTrue(quarantine_todo_path.exists())
            self.assertTrue(manual_review_path.exists())

            registry_payload_out = json.loads(registry_todo_path.read_text(encoding="utf-8"))
            quarantine_payload_out = json.loads(quarantine_todo_path.read_text(encoding="utf-8"))
            self.assertEqual(registry_payload_out["summary"]["needs_registry"], 2)
            self.assertEqual(quarantine_payload_out["summary"]["quarantine"], 1)

            registry_groups = registry_payload_out["groups"]
            self.assertEqual([g["brand_key"] for g in registry_groups], ["asus", None])
            self.assertEqual([g["category"] for g in registry_groups], ["MB", "SSD"])

            manual_rows = [json.loads(line) for line in manual_review_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(manual_rows), 1)
            self.assertIsInstance(manual_rows[0]["matched_tokens"], list)
            self.assertIsInstance(manual_rows[0]["retail_title"], str)


if __name__ == "__main__":
    unittest.main()
