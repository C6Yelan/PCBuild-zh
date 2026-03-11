# backend/tools/crawler/dq_check_json.py
from __future__ import annotations

import argparse
from pathlib import Path

from backend.services.crawler.dq_gate import run_dq_gate
from backend.tools.crawler.artifact_io import read_json_file
from backend.tools.crawler.dq_reports import format_dq_gate_result_line, write_dq_artifacts


def main() -> int:
    ap = argparse.ArgumentParser(description="Run T4 DQ gate against a JSON list file.")
    ap.add_argument("--input", required=True, help="Path to a JSON file (list of items).")
    ap.add_argument("--outdir", required=True, help="Output directory for dq_report/pass/quarantine.")
    args = ap.parse_args()

    in_path = Path(args.input).resolve()
    out_dir = Path(args.outdir).resolve()

    data = read_json_file(in_path)
    if not isinstance(data, list):
        raise SystemExit(f"input must be a JSON list, got {type(data).__name__}")

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

    # fail-fast：只要有 error-level findings，就回非 0（讓 pipeline/CI 能擋下來）
    return 2 if rep.errors > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
