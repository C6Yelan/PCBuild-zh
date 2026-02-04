# backend/tools/crawler/dq_check_dir.py
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from backend.services.crawler.dq_gate import run_dq_gate


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+") # 允許字元：英文字母、數字、點、底線、連字號


def _read_json(path: Path) -> Any: # 將 json 檔案反序列化成 Python 物件
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, obj: Any) -> None: # 將 Python 物件序列化成 json 檔案，並保留中文原樣
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def _safe_part_name(s: str) -> str: # 將字串轉換成安全的檔案/目錄名稱
    s = (s or "-").strip()
    s = _SAFE_NAME_RE.sub("_", s)
    return s.strip("_") or "-"


def main() -> int:
    ap = argparse.ArgumentParser(description="Run T4 DQ gate for every JSON list file in a directory.")
    ap.add_argument("--indir", required=True, help="Directory containing JSON list files (T3 pass outputs).") # 輸入目錄
    ap.add_argument("--outroot", required=True, help="Root output dir. Each part will be written to outroot/<part>/") # 輸出目錄
    ap.add_argument("--pattern", default="*.json", help='Glob pattern (default: "*.json").') # 檔案匹配模式
    ap.add_argument("--fail-fast", action="store_true", help="Stop at first part with errors>0.") # 失敗即停
    args = ap.parse_args()

    in_dir = Path(args.indir).resolve() # 解析並取得輸入目錄的絕對路徑
    out_root = Path(args.outroot).resolve() # 解析並取得輸出目錄的絕對路徑

    if not in_dir.is_dir(): # 檢查輸入路徑是否為目錄
        raise SystemExit(f"indir is not a directory: {in_dir}")

    files = sorted(in_dir.glob(args.pattern)) # 用 Unix shell 類似規則找檔（*, ?, [] 等）
    if not files:
        raise SystemExit(f"no files matched pattern={args.pattern} under {in_dir}")

    any_errors = False

    for fpath in files:
        data = _read_json(fpath)
        if not isinstance(data, list): # 若不是 JSON 陣列，則報錯並退出
            raise SystemExit(f"input must be a JSON list: {fpath} (got {type(data).__name__})")

        result = run_dq_gate(data) # 執行 DQ Gate，取得結果
        rep = result.report
        part = _safe_part_name(rep.category) # 用報表 category 當資料夾名（但先做字元清理）

        out_dir = out_root / part
        _write_json(out_dir / "dq_report.json", rep.to_dict())
        _write_json(out_dir / "dq_pass.json", result.passed_items)
        _write_json(out_dir / "dq_quarantine.json", result.quarantined_items)

        print(
            "category=dq event=dq_gate_result part=%s total=%d passed=%d quarantined=%d errors=%d warnings=%d infos=%d input=%s"
            % (
                rep.category,
                rep.total,
                rep.passed,
                rep.quarantined,
                rep.errors,
                rep.warnings,
                rep.infos,
                str(fpath),
            )
        )

        if rep.errors > 0: # 有錯誤則標記並視需要退出
            any_errors = True
            if args.fail_fast:
                return 2

    return 2 if any_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
