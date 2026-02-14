from __future__ import annotations

import io
import subprocess
import unittest
from contextlib import redirect_stderr
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


if __name__ == "__main__":
    unittest.main()
