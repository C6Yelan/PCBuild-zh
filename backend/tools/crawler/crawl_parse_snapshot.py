# backend/tools/crawl_parse_snapshot.py
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from backend.services.crawler.sources import SourceId
from backend.services.crawler.parsers import get_listing_parser
from backend.services.crawler.schema_gate.validate import SchemaGateError, validate_payload_fail_fast
from backend.services.crawler.dq_gate import run_dq_gate


def _write_json_atomic(path: Path, obj: Any) -> None:
    """
    原子寫入：先寫到同資料夾的 tmp，再用 os.replace 覆蓋目標檔，避免中途失敗留下半截檔。
    注意：tmp 必須在同一個資料夾/檔案系統上，replace 才能達成原子替換語意。
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True, choices=[s.value for s in SourceId])
    ap.add_argument("--snapshot-dir", required=True, help="包含 meta.json 與 body.txt 的資料夾")
    ap.add_argument(
        "--dq-outdir",
        default=None,
        help="(optional) 落檔 DQ 產物：dq_report.json / dq_pass.json / dq_quarantine.json",
    )
    args = ap.parse_args()

    snap = Path(args.snapshot_dir).resolve()
    meta = json.loads((snap / "meta.json").read_text(encoding="utf-8"))
    html = (snap / "body.txt").read_text(encoding="utf-8", errors="replace")

    parser = get_listing_parser(SourceId(args.source))
    items = parser.parse_listings(html=html, page_url=meta.get("final_url") or meta["url"])
    payload = [item.__dict__ for item in items]

    # T3: schema gate
    try:
        validate_payload_fail_fast(source_id=args.source, payload=payload)
    except SchemaGateError as e:
        print(json.dumps(e.report, ensure_ascii=False, indent=2), file=sys.stderr)
        return 2

    # T4: DQ gate
    dq = run_dq_gate(payload)
    rep = dq.report

    # stderr：結構化一行 log（不污染 stdout JSON）
    print(
        "category=dq event=dq_gate_result part=%s total=%d passed=%d quarantined=%d errors=%d warnings=%d infos=%d snapshot_dir=%s"
        % (
            rep.category,
            rep.total,
            rep.passed,
            rep.quarantined,
            rep.errors,
            rep.warnings,
            rep.infos,
            str(snap),
        ),
        file=sys.stderr,
    )

    # 落檔（無論成功/失敗都落，方便追查）
    if args.dq_outdir:
        outdir = Path(args.dq_outdir).resolve()
        _write_json_atomic(outdir / "dq_report.json", rep.to_dict())
        _write_json_atomic(outdir / "dq_pass.json", dq.passed_items)
        _write_json_atomic(outdir / "dq_quarantine.json", dq.quarantined_items)

    # fail-fast：error-level findings 就阻斷
    if rep.errors > 0:
        print(json.dumps(rep.to_dict(), ensure_ascii=False, indent=2), file=sys.stderr)
        return 2

    # stdout：只輸出 pass（讓你原本的 `> temp/零件.json` 照舊可用）
    print(json.dumps(dq.passed_items, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
