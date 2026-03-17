# backend/tools/crawler/dq/cli_json.py
from __future__ import annotations

import argparse
from pathlib import Path

from backend.services.crawler.dq_gate import run_dq_gate
from backend.tools.crawler.dq.reports import format_dq_gate_result_line, write_dq_artifacts
from backend.tools.crawler.io.artifact_io import read_json_file, require_json_list


def main() -> int:
    ap = argparse.ArgumentParser(description="Run T4 DQ gate against a JSON list file.")
    ap.add_argument("--input", required=True, help="Path to a JSON file (list of items).")
    ap.add_argument("--outdir", required=True, help="Output directory for dq_report/pass/quarantine.")
    args = ap.parse_args()

    in_path = Path(args.input).resolve()
    out_dir = Path(args.outdir).resolve()

    data = require_json_list(
        read_json_file(in_path),
        type_error="input must be a JSON list, got {type_name}",
    )

    result = run_dq_gate(data)

    write_dq_artifacts(
        outdir=out_dir,
        report=result.report.to_dict(),
        passed_items=result.passed_items,
        quarantined_items=result.quarantined_items,
    )

    rep = result.report
    print(
        format_dq_gate_result_line(
            report=rep,
            location_key="input",
            location_value=in_path,
        )
    )

    return 2 if rep.errors > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
