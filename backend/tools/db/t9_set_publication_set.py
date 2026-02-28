# backend/tools/db/t9_set_publication_set.py
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from uuid import UUID

import sqlalchemy as sa

from backend.db import SessionLocal
from backend.models.crawler_publication import (
    CrawlerPublicationSet,
    CrawlerPublicationSetMember,
    CrawlerPublicationSetPointer,
)
from backend.models.crawler_staging import CrawlerIngestRun

CATEGORY_ALIASES: dict[str, str] = {
    "cpu": "CPU",
    "mb": "MB",
    "gpu": "GPU",
    "ram": "RAM",
}


def _canonicalize_category(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        return ""
    return CATEGORY_ALIASES.get(value.lower(), value.upper())


def _parse_category_mapping(pairs: list[str]) -> dict[str, UUID]:
    mapping: dict[str, UUID] = {}
    for pair in pairs:
        if "=" not in pair:
            raise SystemExit(f"invalid --cat value: {pair!r}, expected CATEGORY=RUN_ID")
        raw_category, raw_run_id = pair.split("=", 1)
        category = _canonicalize_category(raw_category)
        if not category:
            raise SystemExit(f"invalid category in --cat: {pair!r}")
        run_id_text = raw_run_id.strip()
        if not run_id_text:
            raise SystemExit(f"missing run_id in --cat: {pair!r}")
        run_id = UUID(run_id_text)
        if category in mapping:
            raise SystemExit(f"duplicated category in --cat: {category}")
        mapping[category] = run_id
    return mapping


def _members_by_publication(db, *, publication_id: UUID) -> dict[str, str]:
    rows = db.execute(
        sa.select(
            CrawlerPublicationSetMember.category,
            CrawlerPublicationSetMember.run_id,
        )
        .where(CrawlerPublicationSetMember.publication_id == publication_id)
        .order_by(CrawlerPublicationSetMember.id.asc())
    ).all()
    return {
        _canonicalize_category(str(category)): str(run_id)
        for category, run_id in rows
    }


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="T9: manage publication set pointer (env -> publication_set_id)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp_list = sub.add_parser("list", help="list latest publication_set by env")
    sp_list.add_argument("--env", default="prod", help="env name (default: prod)")
    sp_list.add_argument("--limit", type=int, default=5, help="max rows (default: 5)")

    sp_create = sub.add_parser("create", help="create a new publication_set with category->run mapping")
    sp_create.add_argument("--env", default="prod", help="env name (default: prod)")
    sp_create.add_argument("--note", default=None, help="optional note")
    sp_create.add_argument(
        "--cat",
        action="append",
        required=True,
        help="category mapping, e.g. --cat CPU=<run_id> (repeatable)",
    )
    sp_create.add_argument(
        "--set-pointer",
        action="store_true",
        help="also update crawler_publication_set_pointer for this env",
    )

    sp_set = sub.add_parser("set-pointer", help="set env pointer to an existing publication_set")
    sp_set.add_argument("--env", default="prod", help="env name (default: prod)")
    sp_set.add_argument("--publication-id", required=True, help="target publication_id (UUID)")

    return ap


def _run_list(db, *, env: str, limit: int) -> dict:
    limited = max(1, min(int(limit), 200))
    pointer = db.get(CrawlerPublicationSetPointer, env)
    rows = db.execute(
        sa.select(CrawlerPublicationSet)
        .where(CrawlerPublicationSet.env == env)
        .order_by(CrawlerPublicationSet.created_at.desc())
        .limit(limited)
    ).scalars().all()

    publication_sets: list[dict] = []
    for item in rows:
        publication_sets.append(
            {
                "env": item.env,
                "publication_id": str(item.publication_id),
                "created_at": item.created_at.isoformat(),
                "note": item.note,
                "members": _members_by_publication(db, publication_id=item.publication_id),
            }
        )

    return {
        "ok": True,
        "env": env,
        "pointer_publication_id": None if pointer is None else str(pointer.publication_id),
        "publication_sets": publication_sets,
    }


def _run_create(db, *, env: str, note: str | None, cat_pairs: list[str], set_pointer: bool) -> dict:
    members = _parse_category_mapping(cat_pairs)

    with db.begin():
        existing_runs = set(
            db.execute(
                sa.select(CrawlerIngestRun.run_id).where(CrawlerIngestRun.run_id.in_(list(members.values())))
            ).scalars()
        )
        missing_runs = [str(run_id) for run_id in members.values() if run_id not in existing_runs]
        if missing_runs:
            raise SystemExit(f"run_id not found in crawler_ingest_run: {missing_runs}")

        publication_set = CrawlerPublicationSet(env=env, note=note)
        db.add(publication_set)
        db.flush()
        publication_id = publication_set.publication_id

        for category, run_id in members.items():
            db.add(
                CrawlerPublicationSetMember(
                    publication_id=publication_id,
                    category=category,
                    run_id=run_id,
                )
            )

        pointer_changed = False
        if set_pointer:
            pointer = db.get(CrawlerPublicationSetPointer, env)
            now = datetime.now(timezone.utc)
            if pointer is None:
                db.add(
                    CrawlerPublicationSetPointer(
                        env=env,
                        publication_id=publication_id,
                        updated_at=now,
                    )
                )
            else:
                pointer.publication_id = publication_id
                pointer.updated_at = now
            pointer_changed = True

    return {
        "ok": True,
        "action": "create",
        "env": env,
        "publication_id": str(publication_id),
        "members": {category: str(run_id) for category, run_id in members.items()},
        "pointer_changed": pointer_changed,
    }


def _run_set_pointer(db, *, env: str, publication_id_text: str) -> dict:
    publication_id = UUID(publication_id_text)

    with db.begin():
        publication_set = db.get(CrawlerPublicationSet, publication_id)
        if publication_set is None:
            raise SystemExit(f"publication_id not found: {publication_id}")

        pointer = db.get(CrawlerPublicationSetPointer, env)
        now = datetime.now(timezone.utc)
        if pointer is None:
            db.add(
                CrawlerPublicationSetPointer(
                    env=env,
                    publication_id=publication_id,
                    updated_at=now,
                )
            )
        else:
            pointer.publication_id = publication_id
            pointer.updated_at = now

    return {
        "ok": True,
        "action": "set-pointer",
        "env": env,
        "publication_id": str(publication_id),
        "members": _members_by_publication(db, publication_id=publication_id),
    }


def main() -> int:
    ap = _build_parser()
    args = ap.parse_args()

    env = (getattr(args, "env", "prod") or "").strip()
    if not env:
        raise SystemExit("env cannot be empty")

    with SessionLocal() as db:
        if args.cmd == "list":
            result = _run_list(db, env=env, limit=int(args.limit))
        elif args.cmd == "create":
            result = _run_create(
                db,
                env=env,
                note=args.note,
                cat_pairs=list(args.cat),
                set_pointer=bool(args.set_pointer),
            )
        elif args.cmd == "set-pointer":
            result = _run_set_pointer(db, env=env, publication_id_text=args.publication_id)
        else:
            raise SystemExit(f"unsupported command: {args.cmd}")

    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
