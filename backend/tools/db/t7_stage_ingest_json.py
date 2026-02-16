# backend/tools/db/t7_stage_ingest_json.py
from __future__ import annotations

import argparse
import json
import sys
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from backend.db import SessionLocal
from backend.services.crawler.staging.repo import create_ingest_run, upsert_stg_items


def _load_items(path: str) -> list[dict[str, Any]]:
    """讀取輸入 JSON 並正規化成 list[dict]"""
    if path == "-":
        data = json.load(sys.stdin)
    else:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict) and isinstance(data.get("items"), list):
        items = data["items"]
    else:
        raise SystemExit("輸入 JSON 格式不符：預期為 list，或 {\"items\": [...]}。")

    out: list[dict[str, Any]] = []
    for i, it in enumerate(items):
        if not isinstance(it, dict):
            raise SystemExit(f"第 {i} 筆不是 object/dict。")
        out.append(it)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="T7: ingest canonical JSON into staging (ORM only)")
    ap.add_argument("--source", required=True, help="e.g. coolpc")
    ap.add_argument("--note", default=None)
    ap.add_argument("--input", required=True, help="JSON file path, or '-' for stdin")
    ap.add_argument("--run-id", default=None, help="optional UUID; else auto-generate")
    args = ap.parse_args()

    run_id: UUID = UUID(args.run_id) if args.run_id else uuid4()
    items = _load_items(args.input)

    # 交易框架：with session.begin() 會自動 commit/rollback（ORM 標準用法）
    # 參考 SQLAlchemy Session 交易管理文件
    # https://docs.sqlalchemy.org/en/latest/orm/session_basics.html
    with SessionLocal() as db:
        with db.begin():
            rid = create_ingest_run(db, source=args.source, note=args.note, run_id=run_id)
            inserted, updated = upsert_stg_items(db, run_id=rid, source=args.source, items=items)

    print(json.dumps({"run_id": str(run_id), "inserted": inserted, "updated": updated}, ensure_ascii=False))


if __name__ == "__main__":
    main()
