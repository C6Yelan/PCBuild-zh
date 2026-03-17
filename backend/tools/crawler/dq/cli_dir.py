# backend/tools/crawler/dq/cli_dir.py
from __future__ import annotations

import argparse
import re
from pathlib import Path

from backend.services.crawler.dq_gate import run_dq_gate
from backend.tools.crawler.dq.reports import format_dq_gate_result_line, write_dq_artifacts
from backend.tools.crawler.io.artifact_io import read_json_file, require_json_list


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_part_name(s: str) -> str:
    s = (s or "-").strip()
    s = _SAFE_NAME_RE.sub("_", s)
    return s.strip("_") or "-"


def main() -> int:
    ap = argparse.ArgumentParser(description="Run T4 DQ gate for every JSON list file in a directory.")
    ap.add_argument("--indir", required=True, help="Directory containing JSON list files (T3 pass outputs).")
    ap.add_argument("--outroot", required=True, help="Root output dir. Each part will be written to outroot/<part>/")
    ap.add_argument("--pattern", default="*.json", help='Glob pattern (default: "*.json").')
    ap.add_argument("--fail-fast", action="store_true", help="Stop at first part with errors>0.")
    args = ap.parse_args()

    in_dir = Path(args.indir).resolve()
    out_root = Path(args.outroot).resolve()

    if not in_dir.is_dir():
        raise SystemExit(f"indir is not a directory: {in_dir}")

    files = sorted(in_dir.glob(args.pattern))
    if not files:
        raise SystemExit(f"no files matched pattern={args.pattern} under {in_dir}")

    any_errors = False

    for fpath in files:
        data = require_json_list(
            read_json_file(fpath),
            type_error=f"input must be a JSON list: {fpath} (got {{type_name}})",
        )

        result = run_dq_gate(data)
        rep = result.report
        part = _safe_part_name(rep.category)

        out_dir = out_root / part
        write_dq_artifacts(
            outdir=out_dir,
            report=rep.to_dict(),
            passed_items=result.passed_items,
            quarantined_items=result.quarantined_items,
        )

        print(
            format_dq_gate_result_line(
                report=rep,
                location_key="input",
                location_value=fpath,
            )
        )

        if rep.errors > 0:
            any_errors = True
            if args.fail_fast:
                return 2

    return 2 if any_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
