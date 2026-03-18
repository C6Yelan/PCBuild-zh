# backend/tools/db/staging_gate_writes.py
"""Gate-result payload builders for crawler staging runtimes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from backend.services.crawler.staging.conventions import make_item_key
from backend.services.crawler.staging.repo import StagingGateResultWrite


def build_json_gate_result_writes(
    *,
    source: str,
    items: list[dict[str, Any]],
    gate_results: list[dict[str, Any]],
) -> list[StagingGateResultWrite]:
    items_by_url = _build_item_lookup(items)
    writes: list[StagingGateResultWrite] = []

    for gate_result in gate_results:
        _validate_gate_result_input(gate_result)
        writes.append(
            StagingGateResultWrite(
                item_key=_resolve_gate_item_key(
                    source=source,
                    gate_result=gate_result,
                    items_by_url=items_by_url,
                ),
                gate_name=str(gate_result["gate_name"]),
                status=str(gate_result["status"]),
                detail_json=(
                    gate_result.get("detail_json")
                    if isinstance(gate_result.get("detail_json"), dict)
                    else None
                ),
            )
        )

    return writes


def build_snapshot_gate_result_writes(
    *,
    source: str,
    snapshot_dir: str,
    artifact_dir: Path,
    items: list[dict[str, Any]],
    crawl_rc: int,
    enable_t5: bool,
    dq_report: Any,
    dq_meta: dict[str, Any] | None,
    t5_summary: Any,
    t5_meta: dict[str, Any] | None,
) -> list[StagingGateResultWrite]:
    snapshot_name = str(Path(snapshot_dir).name)
    t5_status = _resolve_t5_status(crawl_rc=crawl_rc, t5_summary=t5_summary)
    writes: list[StagingGateResultWrite] = []

    for item in items:
        item_key = make_item_key(source, item)
        writes.append(
            StagingGateResultWrite(
                item_key=item_key,
                gate_name="t4_dq",
                status="pass",
                detail_json={
                    "artifact_dir": str(artifact_dir),
                    "snapshot_dir": snapshot_name,
                    "dq_report": dq_meta,
                    "dq_report_keys": list(dq_report.keys()) if isinstance(dq_report, dict) else None,
                },
            )
        )

        if enable_t5:
            writes.append(
                StagingGateResultWrite(
                    item_key=item_key,
                    gate_name="t5_link",
                    status=t5_status,
                    detail_json={
                        "artifact_dir": str(artifact_dir),
                        "snapshot_dir": snapshot_name,
                        "t5_summary": t5_meta,
                        "t5_summary_keys": list(t5_summary.keys()) if isinstance(t5_summary, dict) else None,
                    },
                )
            )

    return writes


def _resolve_t5_status(*, crawl_rc: int, t5_summary: Any) -> str:
    status = "pass"
    if crawl_rc != 0:
        status = "fail"
    if isinstance(t5_summary, dict) and int(t5_summary.get("non_match") or 0) > 0:
        status = "fail"
    return status


def _validate_gate_result_input(gate_result: dict[str, Any]) -> None:
    if not gate_result.get("gate_name"):
        raise ValueError("gate_results 缺 gate_name")
    if gate_result.get("status") not in ("pass", "fail"):
        raise ValueError("gate_results.status 只能是 'pass' 或 'fail'")
    if not gate_result.get("item_key") and not gate_result.get("url"):
        raise ValueError("gate_results 必須提供 item_key 或 url 其中之一")


def _build_item_lookup(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_url: dict[str, dict[str, Any]] = {}
    for item in items:
        url = item.get("url")
        if isinstance(url, str) and url:
            by_url[url] = item
    return by_url


def _resolve_gate_item_key(
    *,
    source: str,
    gate_result: dict[str, Any],
    items_by_url: dict[str, dict[str, Any]],
) -> str:
    item_key = gate_result.get("item_key")
    if item_key:
        return str(item_key)

    item = items_by_url.get(str(gate_result["url"]))
    if item is None:
        raise ValueError(f"gate_results url 找不到對應 item: {gate_result['url']}")
    return make_item_key(source, item)


__all__ = [
    "build_json_gate_result_writes",
    "build_snapshot_gate_result_writes",
]
