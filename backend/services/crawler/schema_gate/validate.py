# backend/services/crawler/schema_gate/validate.py
from __future__ import annotations

import json
from dataclasses import is_dataclass
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


def validate_payload_fail_fast(*, source_id: str, payload: list[Any]) -> None: # 僅針對 CoolPC 的 CPU 類別進行 schema 驗證
    """
    Fail-fast schema gate.

    CPU only for now:
      - if payload category == "CPU": validate with CoolPC CPU schema
      - any validation error -> raise SchemaGateError(report)
    """
    if not payload: # 空的 payload 不進行驗證，直接返回
        return

    # payload is list[dict] (from item.__dict__)
    # 從 payload 中提取所有的 category 值，並檢查是否包含 "CPU"
    categories = {((row or {}).get("category")) for row in payload if isinstance(row, dict)}
    if "CPU" not in categories: # 如果沒有 "CPU" 類別，則不進行驗證，直接返回
        return

    if source_id != "coolpc": # 如果來源不是 coolpc，則不進行驗證，直接返回
        # CPU schema not defined for other sources in this step.
        return

    schema = _load_schema("schemas/coolpc/cpu.schema.json") # 建立 JSON schema 驗證器
    validator = Draft202012Validator(schema, format_checker=FormatChecker()) # 使用 Draft202012Validator 進行驗證

    errors: list[dict[str, Any]] = []
    for idx, row in enumerate(payload): # 逐一驗證 payload 中的每一項
        if not isinstance(row, dict): # 如果該項不是字典，則記錄錯誤並繼續
            errors.append(
                {
                    "index": idx,
                    "path": "",
                    "message": f"Item is not an object/dict (got {type(row).__name__})",
                }
            )
            continue

        for e in validator.iter_errors(row): # 對每一項進行 schema 驗證，收集錯誤訊息
            path = "/" + "/".join(str(p) for p in e.absolute_path)  # e.absolute_path 是錯誤發生的位置路徑
            errors.append(
                {
                    "index": idx,
                    "path": path if path != "/" else "",
                    "message": e.message, # e.message 是錯誤訊息(人類可讀訊息)
                    "validator": e.validator, # e.validator 是觸發錯誤的驗證器名稱(例如：required, type)
                    "schema_path": "/" + "/".join(str(p) for p in e.absolute_schema_path),  # e.absolute_schema_path 是錯誤發生的 schema 路徑
                }
            )

    if errors:
        report = { # 如果有錯誤，則建立報告並引發 SchemaGateError 例外，包含錯誤詳情
            "source_id": source_id,
            "categories": sorted(c for c in categories if c),
            "error_count": len(errors),
            "errors": errors[:200],  # 防止爆量；先截 200 筆
        }
        raise SchemaGateError(report=report)
