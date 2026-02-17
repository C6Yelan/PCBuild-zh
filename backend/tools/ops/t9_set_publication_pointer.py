# backend/tools/ops/t9_set_publication_pointer.py
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from uuid import UUID

from backend.db import SessionLocal
from backend.models.crawler_publication import CrawlerPublication, CrawlerPublicationPointer


def main() -> int:
    ap = argparse.ArgumentParser(description="T9: set publication pointer (env -> published run_id)")
    ap.add_argument("--env", default="prod", help="pointer env (default: prod)")
    ap.add_argument("--run-id", required=True, help="target published run_id (UUID)")
    ap.add_argument("--dry-run", action="store_true", help="print changes only; no DB write")
    args = ap.parse_args()

    env = (args.env or "").strip()
    if not env:
        raise SystemExit("env cannot be empty")

    run_id = UUID(args.run_id)

    db = SessionLocal()
    try:
        with db.begin():
            pub = db.get(CrawlerPublication, run_id)
            if pub is None:
                raise SystemExit(f"run_id is not published yet: {run_id}")

            ptr = db.get(CrawlerPublicationPointer, env)
            before = None if ptr is None else str(ptr.run_id)

            if args.dry_run:
                print(
                    json.dumps(
                        {
                            "ok": True,
                            "dry_run": True,
                            "env": env,
                            "before_run_id": before,
                            "after_run_id": str(run_id),
                        },
                        ensure_ascii=False,
                    )
                )
                return 0

            now = datetime.now(timezone.utc)
            if ptr is None:
                db.add(CrawlerPublicationPointer(env=env, run_id=run_id, updated_at=now))
            else:
                ptr.run_id = run_id
                ptr.updated_at = now

        print(json.dumps({"ok": True, "env": env, "run_id": str(run_id)}, ensure_ascii=False))
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
