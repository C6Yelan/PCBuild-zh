from __future__ import annotations

"""Typesense parts index ops CLI.

Run this CLI inside the `fastapi` container on the server host. Windows + WSL
development machines should only edit code and run non-Docker local checks.
"""

import argparse
import json
from typing import Sequence

from backend.core.settings import get_settings
from backend.db import SessionLocal
from backend.models.crawler_publication import CrawlerPublicationPointer
from backend.services.chat.context_pack.typesense_adapter import (
    TypesenseClient,
    build_parts_index_batch_stmt,
    build_typesense_document,
)


def _ensure_publication_pointer(env: str) -> None:
    with SessionLocal() as db:
        ptr = db.get(CrawlerPublicationPointer, env)
        if ptr is None:
            raise RuntimeError(f"crawler_publication_pointer not found for env={env!r}; please publish first")


def ensure_collection(*, recreate: bool = False) -> dict[str, object]:
    settings = get_settings()
    client = TypesenseClient(settings)
    client.create_collection(force=recreate)
    return {
        "ok": True,
        "collection": client.collection_name,
        "recreated": recreate,
    }


def sync_parts(*, env: str, batch_size: int) -> dict[str, object]:
    settings = get_settings()
    client = TypesenseClient(settings)
    client.create_collection(force=False)
    _ensure_publication_pointer(env)

    imported_success = 0
    imported_failed = 0
    total_rows = 0
    offset = 0

    with SessionLocal() as db:
        while True:
            rows = list(
                db.execute(
                    build_parts_index_batch_stmt(
                        env=env,
                        limit=batch_size,
                        offset=offset,
                    )
                ).mappings()
            )
            if not rows:
                break

            documents = [build_typesense_document(row, env=env) for row in rows]
            summary = client.import_documents(documents)
            imported_success += summary["success"]
            imported_failed += summary["failed"]
            total_rows += len(rows)
            offset += len(rows)

    return {
        "ok": imported_failed == 0,
        "collection": client.collection_name,
        "env": env,
        "batch_size": batch_size,
        "rows_read": total_rows,
        "imported_success": imported_success,
        "imported_failed": imported_failed,
    }


def rebuild_parts(*, env: str, batch_size: int) -> dict[str, object]:
    ensure_collection(recreate=True)
    return sync_parts(env=env, batch_size=batch_size)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage Typesense parts collection.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ensure_parser = subparsers.add_parser("ensure-collection")
    ensure_parser.add_argument("--recreate", action="store_true")

    sync_parser = subparsers.add_parser("sync")
    sync_parser.add_argument("--env", default="prod")
    sync_parser.add_argument("--batch-size", type=int, default=500)

    rebuild_parser = subparsers.add_parser("rebuild")
    rebuild_parser.add_argument("--env", default="prod")
    rebuild_parser.add_argument("--batch-size", type=int, default=500)

    args = parser.parse_args(argv)

    if args.command == "ensure-collection":
        summary = ensure_collection(recreate=bool(args.recreate))
    elif args.command == "sync":
        summary = sync_parts(env=str(args.env), batch_size=max(1, int(args.batch_size)))
    else:
        summary = rebuild_parts(env=str(args.env), batch_size=max(1, int(args.batch_size)))

    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0 if summary.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
