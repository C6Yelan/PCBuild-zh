# backend/tools/ops/t9_list_publications.py
from __future__ import annotations

import argparse
import json
from typing import Any

import sqlalchemy as sa

from backend.db import SessionLocal
from backend.models.crawler_publication import CrawlerPublication, CrawlerPublicationPointer


def _stats_summary(stats: dict[str, Any] | None) -> dict[str, Any]:
    s = stats or {}
    keys = [
        "source",
        "checked_at",
        "gate_total",
        "gate_pass",
        "gate_fail",
        "item_total",
        "item_pass",
        "item_fail",
        "item_no_gate",
    ]
    return {k: s.get(k) for k in keys if k in s}


def main() -> int:
    ap = argparse.ArgumentParser(description="T9: list publications & pointers")
    ap.add_argument("--limit", type=int, default=20, help="number of publications to show (default: 20)")
    ap.add_argument("--env", default=None, help="filter pointer env (default: all)")
    ap.add_argument("--with-stats-json", action="store_true", help="include full stats_json (may be large)")
    args = ap.parse_args()

    limit = max(1, min(int(args.limit), 200))

    db = SessionLocal()
    try:
        # pointers
        ptr_stmt = sa.select(CrawlerPublicationPointer)
        if args.env:
            ptr_stmt = ptr_stmt.where(CrawlerPublicationPointer.env == args.env)

        ptrs = db.execute(ptr_stmt).scalars().all()
        pointers = {
            p.env: {"run_id": str(p.run_id), "updated_at": p.updated_at.isoformat()}
            for p in ptrs
        }

        # publications (latest first)
        pubs = (
            db.execute(
                sa.select(CrawlerPublication)
                .order_by(CrawlerPublication.published_at.desc())
                .limit(limit)
            )
            .scalars()
            .all()
        )

        out_pubs: list[dict[str, Any]] = []
        for pub in pubs:
            d: dict[str, Any] = {
                "run_id": str(pub.run_id),
                "published_at": pub.published_at.isoformat(),
                "note": pub.note,
            }
            if args.with_stats_json:
                d["stats_json"] = pub.stats_json
            else:
                d["stats"] = _stats_summary(pub.stats_json)
            out_pubs.append(d)

        print(
            json.dumps(
                {"ok": True, "pointers": pointers, "publications": out_pubs},
                ensure_ascii=False,
            )
        )
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
