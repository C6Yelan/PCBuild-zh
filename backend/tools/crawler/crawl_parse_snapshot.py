# backend/tools/crawl_parse_snapshot.py
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from backend.services.crawler.sources import SourceId
from backend.services.crawler.parsers import get_listing_parser
from backend.services.crawler.schema_gate.validate import SchemaGateError, validate_payload_fail_fast
from backend.services.crawler.dq_gate import run_dq_gate


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True, choices=[s.value for s in SourceId])
    ap.add_argument("--snapshot-dir", required=True, help="包含 meta.json 與 body.txt 的資料夾")
    args = ap.parse_args()

    snap = Path(args.snapshot_dir).resolve()
    meta = json.loads((snap / "meta.json").read_text(encoding="utf-8"))
    html = (snap / "body.txt").read_text(encoding="utf-8", errors="replace")

    parser = get_listing_parser(SourceId(args.source))
    items = parser.parse_listings(html=html, page_url=meta.get("final_url") or meta["url"])

    payload = [item.__dict__ for item in items]

    try:
        validate_payload_fail_fast(source_id=args.source, payload=payload)
    except SchemaGateError as e:
        # fail fast：輸出報告到 stderr，並停止
        print(json.dumps(e.report, ensure_ascii=False, indent=2), file=sys.stderr)
        return 2

    # T4: DQ gate（fail-fast on error-level findings）
    dq = run_dq_gate(payload)
    rep = dq.report

    # 統一輸出一行結構化 log（stderr，不污染 stdout JSON）
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

    if rep.errors > 0:
        print(json.dumps(rep.to_dict(), ensure_ascii=False, indent=2), file=sys.stderr)
        return 2

    # stdout 只輸出 dq_pass（讓你原本的 `> temp/零件.json` 直接得到可用資料）
    print(json.dumps(dq.passed_items, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
