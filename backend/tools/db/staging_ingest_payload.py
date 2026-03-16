"""JSON payload loaders for T7 ingest CLI/runtime."""

from __future__ import annotations

from backend.tools.crawler.io.artifact_io import read_json_input, require_json_object_list
from backend.tools.db.staging_ingest_models import StageIngestPayload


def load_stage_ingest_payload(path: str) -> StageIngestPayload:
    data = read_json_input(path)

    if isinstance(data, list):
        items = require_json_object_list(
            data,
            type_error='輸入 JSON 格式不符：預期為 list，或 {"items":[...], "gate_results":[...]}。',
            item_error="items 第 {index} 筆不是 object/dict。",
        )
        return StageIngestPayload(items=items, gate_results=[])

    if isinstance(data, dict) and isinstance(data.get("items"), list):
        items = require_json_object_list(
            data["items"],
            type_error='輸入 JSON 格式不符：預期為 list，或 {"items":[...], "gate_results":[...]}。',
            item_error="items 第 {index} 筆不是 object/dict。",
        )
        raw_gate_results = data.get("gate_results") or []
        if not isinstance(raw_gate_results, list):
            raise SystemExit('gate_results 必須是 list（或省略）。')
        gate_results = require_json_object_list(
            raw_gate_results,
            type_error='gate_results 必須是 list（或省略）。',
            item_error="gate_results 第 {index} 筆不是 object/dict。",
        )
        return StageIngestPayload(items=items, gate_results=gate_results)

    raise SystemExit('輸入 JSON 格式不符：預期為 list，或 {"items":[...], "gate_results":[...]}。')


__all__ = ["load_stage_ingest_payload"]
