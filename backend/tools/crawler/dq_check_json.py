# backend/tools/crawler/dq_check_json.py
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from backend.services.crawler.dq_gate import run_dq_gate


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def main() -> int:
    ap = argparse.ArgumentParser(description="Run T4 DQ gate against a JSON list file.")
    ap.add_argument("--input", required=True, help="Path to a JSON file (list of items).")
    ap.add_argument("--outdir", required=True, help="Output directory for dq_report/pass/quarantine.")
    args = ap.parse_args()

    in_path = Path(args.input).resolve()
    out_dir = Path(args.outdir).resolve()

    data = _read_json(in_path)
    if not isinstance(data, list):
        raise SystemExit(f"input must be a JSON list, got {type(data).__name__}")

    result = run_dq_gate(data)

    _write_json(out_dir / "dq_report.json", result.report.to_dict())
    _write_json(out_dir / "dq_pass.json", result.passed_items)
    _write_json(out_dir / "dq_quarantine.json", result.quarantined_items)

    rep = result.report
    print(
        "category=dq event=dq_gate_result part=%s total=%d passed=%d quarantined=%d errors=%d warnings=%d infos=%d input=%s"
        % (
            rep.category,
            rep.total,
            rep.passed,
            rep.quarantined,
            rep.errors,
            rep.warnings,
            rep.infos,
            str(in_path),
        )
    )

    # fail-fast：只要有 error-level findings，就回非 0（讓 pipeline/CI 能擋下來）
    return 2 if rep.errors > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
