# backend/tools/db/t7_stage_ingest_json.py
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from backend.db import SessionLocal
from backend.core.obs_events import ensure_cli_logging, log_loki_event
from backend.services.crawler.staging.repo import (
    create_ingest_run,
    upsert_stg_items,
    upsert_stg_gate_result,
)

_PIPELINE_LOGGER = logging.getLogger("pcbuild.pipeline")


def _get_env() -> str:
    return os.getenv("APP_ENV") or os.getenv("ENV") or "prod"


def _make_item_key(source: str, it: dict[str, Any]) -> str:
    seed = "|".join(
        [
            source,
            str(it.get("category") or ""),
            str(it.get("url") or ""),
            str(it.get("title") or ""),
            str(it.get("sku_hint") or ""),
        ]
    )
    return hashlib.sha1(seed.encode("utf-8")).hexdigest()


def _load_payload(path: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    支援兩種輸入：
    1) list: 視為 items
    2) object: {"items":[...], "gate_results":[...]}，gate_results 可省略
    """
    if path == "-":
        data = json.load(sys.stdin)
    else:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

    if isinstance(data, list):
        items = data
        gate_results: list[dict[str, Any]] = []
    elif isinstance(data, dict) and isinstance(data.get("items"), list):
        items = data["items"]
        gate_results = data.get("gate_results") or []
        if not isinstance(gate_results, list):
            raise SystemExit('gate_results 必須是 list（或省略）。')
    else:
        raise SystemExit('輸入 JSON 格式不符：預期為 list，或 {"items":[...], "gate_results":[...]}。')

    out_items: list[dict[str, Any]] = []
    for i, it in enumerate(items):
        if not isinstance(it, dict):
            raise SystemExit(f"items 第 {i} 筆不是 object/dict。")
        out_items.append(it)

    out_gates: list[dict[str, Any]] = []
    for i, gr in enumerate(gate_results):
        if not isinstance(gr, dict):
            raise SystemExit(f"gate_results 第 {i} 筆不是 object/dict。")
        out_gates.append(gr)

    return out_items, out_gates


def _validate_gate(gr: dict[str, Any]) -> None:
    if not gr.get("gate_name"):
        raise ValueError("gate_results 缺 gate_name")
    if gr.get("status") not in ("pass", "fail"):
        raise ValueError("gate_results.status 只能是 'pass' 或 'fail'")
    # 必須提供 item_key 或 url 其一
    if not gr.get("item_key") and not gr.get("url"):
        raise ValueError("gate_results 必須提供 item_key 或 url 其中之一")


def main() -> int:
    ap = argparse.ArgumentParser(description="T7: ingest canonical JSON into staging (ORM only)")
    ap.add_argument("--source", required=True, help="e.g. coolpc")
    ap.add_argument("--note", default=None)
    ap.add_argument("--input", required=True, help="JSON file path, or '-' for stdin")
    ap.add_argument("--run-id", default=None, help="optional UUID; else auto-generate")
    args = ap.parse_args()

    run_id: UUID = UUID(args.run_id) if args.run_id else uuid4()
    ensure_cli_logging(logger=_PIPELINE_LOGGER)

    src = str(args.source)
    input_name = "stdin" if args.input == "-" else Path(args.input).name
    app_git_sha = (os.getenv("APP_GIT_SHA") or "unknown").strip() or "unknown"
    item_total: int | None = None
    gate_total: int | None = None
    t0 = time.monotonic()

    try:
        items, gate_results = _load_payload(args.input)
        item_total = int(len(items))
        gate_total = int(len(gate_results))

        log_loki_event(
            _PIPELINE_LOGGER,
            event="t7_stage_ingest_started",
            source=src,
            stage="stage",
            env=_get_env(),
            run_id=str(run_id),
            app_git_sha=app_git_sha,
            input=str(args.input),
            input_name=input_name,
            item_total=item_total,
            gate_total=gate_total,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        # 用 url 建索引（若 gate_results 用 url 指向 item）
        by_url: dict[str, dict[str, Any]] = {}
        for it in items:
            url = it.get("url")
            if isinstance(url, str) and url:
                by_url[url] = it

        # SQLAlchemy 建議的交易框架：with Session.begin() 成功 commit、例外 rollback
        # https://docs.sqlalchemy.org/en/latest/orm/session_basics.html
        with SessionLocal() as db:
            with db.begin():
                rid = create_ingest_run(db, source=args.source, note=args.note, run_id=run_id)
                inserted, updated = upsert_stg_items(db, run_id=rid, source=args.source, items=items)

                gate_inserted = 0
                gate_updated = 0
                for gr in gate_results:
                    _validate_gate(gr)

                    item_key = gr.get("item_key")
                    if not item_key:
                        it = by_url.get(str(gr["url"]))
                        if it is None:
                            raise ValueError(f"gate_results url 找不到對應 item: {gr['url']}")
                        item_key = _make_item_key(args.source, it)

                    ins, upd = upsert_stg_gate_result(
                        db,
                        run_id=rid,
                        item_key=str(item_key),
                        gate_name=str(gr["gate_name"]),
                        status=str(gr["status"]),
                        detail_json=(gr.get("detail_json") if isinstance(gr.get("detail_json"), dict) else None),
                    )
                    gate_inserted += ins
                    gate_updated += upd

        log_loki_event(
            _PIPELINE_LOGGER,
            event="t7_stage_ingest_finished",
            source=src,
            stage="stage",
            env=_get_env(),
            run_id=str(run_id),
            app_git_sha=app_git_sha,
            input=str(args.input),
            input_name=input_name,
            item_total=item_total,
            gate_total=gate_total,
            item_inserted=int(inserted),
            item_updated=int(updated),
            gate_inserted=int(gate_inserted),
            gate_updated=int(gate_updated),
            elapsed_ms=int((time.monotonic() - t0) * 1000),
            ended_at=datetime.now(timezone.utc).isoformat(),
        )

        print(
            json.dumps(
                {
                    "run_id": str(run_id),
                    "item_inserted": inserted,
                    "item_updated": updated,
                    "gate_inserted": gate_inserted,
                    "gate_updated": gate_updated,
                },
                ensure_ascii=False,
            )
        )
        return 0
    except (Exception, SystemExit) as e:
        log_loki_event(
            _PIPELINE_LOGGER,
            level=logging.ERROR,
            event="t7_stage_ingest_failed",
            source=src,
            stage="stage",
            env=_get_env(),
            run_id=str(run_id),
            app_git_sha=app_git_sha,
            input=str(args.input),
            input_name=input_name,
            item_total=item_total,
            gate_total=gate_total,
            error=str(e),
            exc_type=type(e).__name__,
            elapsed_ms=int((time.monotonic() - t0) * 1000),
            ended_at=datetime.now(timezone.utc).isoformat(),
        )
        raise


if __name__ == "__main__":
    raise SystemExit(main())
