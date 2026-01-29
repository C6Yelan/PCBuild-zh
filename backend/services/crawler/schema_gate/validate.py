# backend/services/crawler/schema_gate/validate.py
from __future__ import annotations

import json
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


class SchemaGateError(RuntimeError): # 自訂例外類別，用於表示 schema gate 驗證失敗
    def __init__(self, *, report: dict[str, Any]):
        super().__init__("Schema gate validation failed")
        self.report = report


def _load_schema(rel_path: str) -> dict[str, Any]: # 從指定路徑載入 JSON schema，不依賴外部檔案系統和硬編碼路徑
    # rel_path is relative to this package directory
    with resources.files(__package__).joinpath(rel_path).open("r", encoding="utf-8") as f:
        return json.load(f)


# (source_id, category) -> schema file (relative to this package)
# 明確 allowlist：新增 schema 時只需要在這裡加一行 mapping。
_SCHEMA_ALLOWLIST: dict[tuple[str, str], str] = {
    ("coolpc", "CPU"): "schemas/coolpc/cpu.schema.json",
    ("coolpc", "MB"): "schemas/coolpc/mb.schema.json",
    ("coolpc", "RAM"): "schemas/coolpc/ram.schema.json",
    ("coolpc", "SSD"): "schemas/coolpc/ssd.schema.json",
    ("coolpc", "HDD"): "schemas/coolpc/hdd.schema.json",
}


def validate_payload_fail_fast(*, source_id: str, payload: list[Any]) -> None:
    """
    Fail-fast schema gate (allowlist-based).

    - 依 (source_id, category) 選擇 schema
    - 任一筆資料不符合 schema 或缺少 schema mapping -> raise SchemaGateError(report)
    """
    source_id = (source_id or "").strip().lower()
    if not payload:
        return

    # per-run cache：避免重複載入 schema/建立 validator
    validator_cache: dict[str, Draft202012Validator] = {}

    categories: set[str] = set()
    errors: list[dict[str, Any]] = []

    for idx, row in enumerate(payload):
        if not isinstance(row, dict):
            errors.append(
                {
                    "index": idx,
                    "category": None,
                    "path": "",
                    "message": f"Item is not an object/dict (got {type(row).__name__})",
                }
            )
            continue

        raw_cat = row.get("category")
        if not isinstance(raw_cat, str) or not raw_cat.strip():
            errors.append(
                {
                    "index": idx,
                    "category": raw_cat,
                    "path": "/category",
                    "message": "Missing or invalid category",
                }
            )
            continue

        category = raw_cat.strip().upper()
        categories.add(category)

        schema_rel_path = _SCHEMA_ALLOWLIST.get((source_id, category))
        if not schema_rel_path:
            errors.append(
                {
                    "index": idx,
                    "category": category,
                    "path": "",
                    "message": f"No schema registered for (source_id={source_id!r}, category={category!r})",
                }
            )
            continue

        validator = validator_cache.get(schema_rel_path)
        if validator is None:
            schema = _load_schema(schema_rel_path)
            validator = Draft202012Validator(schema, format_checker=FormatChecker())
            validator_cache[schema_rel_path] = validator

        for e in validator.iter_errors(row):
            path = "/" + "/".join(str(p) for p in e.absolute_path)
            errors.append(
                {
                    "index": idx,
                    "category": category,
                    "path": path if path != "/" else "",
                    "message": e.message,
                    "validator": e.validator,
                    "schema_path": "/" + "/".join(str(p) for p in e.absolute_schema_path),
                }
            )

    if errors:
        report = {
            "source_id": source_id,
            "categories": sorted(categories),
            "error_count": len(errors),
            "errors": errors[:200],
        }
        raise SchemaGateError(report=report)
