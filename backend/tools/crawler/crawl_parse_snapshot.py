# backend/tools/crawl_parse_snapshot.py
from __future__ import annotations

import argparse
import json
from pathlib import Path

from backend.services.crawler.sources import SourceId
from backend.services.crawler.parsers import get_listing_parser
from backend.services.crawler.schema_gate.validate import SchemaGateError, validate_payload_fail_fast


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
        import sys
        print(json.dumps(e.report, ensure_ascii=False, indent=2), file=sys.stderr)
        return 2

    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
