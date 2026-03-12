# backend/tools/db/catalog_query_cli.py
from __future__ import annotations

import argparse
import json

from backend.db import SessionLocal
from backend.services.catalog.query import list_products_with_latest_price


def main() -> int:
    ap = argparse.ArgumentParser(description="T8: query catalog products with latest price")
    ap.add_argument("--category", default=None)
    ap.add_argument("--q", default=None)
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--include-specs", action="store_true")
    args = ap.parse_args()

    with SessionLocal() as db:
        rows = list_products_with_latest_price(
            db,
            category=args.category,
            q=args.q,
            limit=args.limit,
            offset=args.offset,
            include_specs=bool(args.include_specs),
        )

    print(json.dumps(rows, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
