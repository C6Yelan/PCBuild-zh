from __future__ import annotations

import io
import json
import subprocess
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from backend.tools.crawler import t6_run_official_reconcile_pipeline as pipeline_cli


class TestT6PipelineCLI(unittest.TestCase):
    @patch("backend.tools.crawler.t6_run_official_reconcile_pipeline.subprocess.run")
    def test_runs_five_phases_in_order(self, mock_run) -> None:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)

        exit_code = pipeline_cli.main(
            [
                "--input",
                "temp/t6_sample_retail.json",
                "--run-dir",
                "temp/t6_pipeline_unittest_run",
            ]
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(mock_run.call_count, 5)

        expected_modules = [
            "backend.tools.crawler.t6_build_official_lookup_plan",
            "backend.tools.crawler.t6_discover_official_candidates",
            "backend.tools.crawler.t6_robots_gate_candidates",
            "backend.tools.crawler.t6_fetch_candidate_evidence",
            "backend.tools.crawler.t6_score_official_candidates",
        ]
        expected_outputs = [
            "plans.json",
            "candidates.jsonl",
            "gated_candidates.jsonl",
            "evidence.jsonl",
            "decisions.jsonl",
        ]

        for idx, call in enumerate(mock_run.call_args_list):
            cmd = call.args[0]
            kwargs = call.kwargs
            self.assertIsInstance(cmd, list)
            self.assertGreaterEqual(len(cmd), 3)
            self.assertEqual(cmd[1], "-m")
            self.assertEqual(cmd[2], expected_modules[idx])
            self.assertFalse(kwargs.get("shell", False))
            self.assertEqual(kwargs.get("check"), False)

            if "--output" in cmd:
                output_value = cmd[cmd.index("--output") + 1]
                self.assertTrue(output_value.endswith(expected_outputs[idx]))

    def test_run_dir_must_be_under_temp(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            with self.assertRaises(SystemExit):
                pipeline_cli.main(
                    [
                        "--input",
                        "temp/t6_sample_retail.json",
                        "--run-dir",
                        "backend/not_allowed",
                    ]
                )

        error_text = stderr.getvalue()
        self.assertIn("--run-dir must be under temp/", error_text)

    @patch("backend.tools.crawler.t6_run_official_reconcile_pipeline.subprocess.run")
    def test_pipeline_propagates_discovery_block_reason_to_decisions(self, mock_run) -> None:
        run_dir = "temp/t6_pipeline_reason_unittest_run"
        project_root = pipeline_cli._project_root()
        resolved_run_dir = (project_root / run_dir).resolve()

        def _arg(cmd: list[str], flag: str) -> str:
            return cmd[cmd.index(flag) + 1]

        def _write_json(path: Path, payload: object) -> None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        def side_effect(cmd: list[str], *, check: bool, shell: bool, cwd: str):
            module = cmd[2]
            if module == "backend.tools.crawler.t6_build_official_lookup_plan":
                plans_path = Path(_arg(cmd, "--output"))
                _write_json(
                    plans_path,
                    [
                        {
                            "retail_url": "https://example.invalid/psu/1",
                            "source": "coolpc",
                            "category": "PSU",
                            "title": "Seasonic FOCUS GX-750",
                            "sku_hint": "FOCUS GX-750",
                            "brand_key": "seasonic",
                            "brand_source": "title_or_sku_hint+registry_alias",
                            "brand_raw": "Seasonic",
                            "allowed_domains": ["example.com"],
                            "query_terms": ["FOCUS GX-750"],
                            "decision": "ok",
                            "decision_notes": "ok",
                        }
                    ],
                )
                return subprocess.CompletedProcess(args=cmd, returncode=0)

            if module == "backend.tools.crawler.t6_discover_official_candidates":
                Path(_arg(cmd, "--output")).write_text("", encoding="utf-8")
                plan_report_path = Path(_arg(cmd, "--plan-report"))
                _write_json(
                    plan_report_path,
                    [
                        {
                            "plan_index": 0,
                            "brand_key": "seasonic",
                            "category": "PSU",
                            "decision": "ok",
                            "allowed_domains": ["example.com"],
                            "registry_used": True,
                            "default_used": False,
                            "entrypoints_tried": [
                                {
                                    "source": "registry",
                                    "url": "https://example.com/sitemap.xml",
                                    "kind": "entrypoint",
                                    "status": "error",
                                    "reason": "blocked",
                                    "detail": "cloudflare_403",
                                }
                            ],
                            "fetched_sitemaps": 1,
                            "parsed_urlsets": 0,
                            "parsed_indexes": 0,
                            "candidates_emitted": 0,
                            "errors": [
                                {
                                    "reason": "blocked",
                                    "detail": "cloudflare_403",
                                    "url": "https://example.com/sitemap.xml",
                                    "source": "registry",
                                }
                            ],
                        }
                    ],
                )
                return subprocess.CompletedProcess(args=cmd, returncode=0)

            if module == "backend.tools.crawler.t6_robots_gate_candidates":
                Path(_arg(cmd, "--output")).write_text("", encoding="utf-8")
                return subprocess.CompletedProcess(args=cmd, returncode=0)

            if module == "backend.tools.crawler.t6_fetch_candidate_evidence":
                Path(_arg(cmd, "--output")).write_text("", encoding="utf-8")
                return subprocess.CompletedProcess(args=cmd, returncode=0)

            if module == "backend.tools.crawler.t6_score_official_candidates":
                from backend.tools.crawler import t6_score_official_candidates as score_cli

                rc = score_cli.main(cmd[3:])
                return subprocess.CompletedProcess(args=cmd, returncode=rc)

            return subprocess.CompletedProcess(args=cmd, returncode=0)

        mock_run.side_effect = side_effect

        exit_code = pipeline_cli.main(
            [
                "--input",
                "temp/t6_sample_retail.json",
                "--run-dir",
                run_dir,
            ]
        )

        self.assertEqual(exit_code, 0)
        decision_path = resolved_run_dir / "decisions.jsonl"
        self.assertTrue(decision_path.exists())
        lines = [line.strip() for line in decision_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        decision = json.loads(lines[0])
        self.assertIn("discovery_blocked", decision.get("decision_reason", ""))


if __name__ == "__main__":
    unittest.main()
