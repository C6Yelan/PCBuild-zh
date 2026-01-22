# backend/services/crawler/parsers/report_analysis.py
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

_BRACKET_SPLIT_RE = re.compile(r"[（(【]")
_SPACE_RE = re.compile(r"\s+")
_LEADING_NOTE_RE = re.compile(r"^\[[^\]]+\]\s*")


def first_line(text: str) -> str:
    if not text:
        return ""
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return text.strip()


def normalize_spaces(text: str) -> str:
    return _SPACE_RE.sub(" ", (text or "")).strip()


def head_before_brackets(text: str) -> str:
    head = _BRACKET_SPLIT_RE.split(text or "", 1)[0]
    return normalize_spaces(head)


def strip_leading_note(text: str) -> str:
    return _LEADING_NOTE_RE.sub("", (text or "")).strip()

_VRAM_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:\d{1,2}\s*G(?:B)?|\d{1,2}GBD\d|\d{1,2}GD\d|O\d{1,2}G)"
    r"(?=[^A-Za-z0-9]|$)"
)
_VRAM_CODE_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:\d{1,2}GBD\d|\d{1,2}GD\d|O\d{1,2}G)(?=[^A-Za-z0-9]|$)"
)
_GPU_ACCESSORY_RE = re.compile(
    r"(?i)(支撐架|支架|支撐|顯示卡支架|GPU\s*holder|holder|bracket|Herculx|"
    r"轉接線|轉接頭|轉接器|轉接|轉換線|延長線|線材)"
)
_MB_BUNDLE_RE = re.compile(r"(?i)(大全配|套裝|優惠組合|組合|主題機殼|玩具總動員|bundle)")
_CPU_KEYWORD_RE = re.compile(r"(?i)(intel|amd|ryzen|threadripper|xeon|pentium|celeron|athlon|core)")
_CPU_ACCESSORY_RE = re.compile(r"(?i)(水冷|散熱器?|冷卻|優惠加購|加購|(?<![含無附])風扇)")

_IMPORTANT_FIELDS = [
    "brand_hint",
    "chipset_hint",
    "chip_hint",
    "vram_gb_hint",
    "product_model_hint",
]


def _load_items(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))

def _count_field_nulls(items: list[dict], field: str) -> tuple[int, int]:
    total = len(items)
    nulls = 0
    for d in items:
        extra = d.get("extra") or {}
        if extra.get(field) is None:
            nulls += 1
    return nulls, total


def _null_ratio(items: list[dict], key: str | None = None) -> tuple[int, int]:
    total = len(items)
    if key is None:
        nulls = sum(1 for d in items if d.get("sku_hint") is None)
        return nulls, total
    nulls = 0
    for d in items:
        extra = d.get("extra") or {}
        if extra.get(key) is None:
            nulls += 1
    return nulls, total


def _fmt_ratio(nulls: int, total: int) -> str:
    if total == 0:
        return "0/0 (0.0%)"
    return f"{nulls}/{total} ({nulls / total:.1%})"

def _format_issue_lines(items: list[dict], formatter, limit: int = 200) -> str:
    if not items:
        return "- (none)"
    lines = [f"- {formatter(d)}" for d in items[:limit]]
    if len(items) > limit:
        lines.append(f"- (truncated, {len(items) - limit} more)")
    return "\n".join(lines)

def _fmt_title(item: dict) -> str:
    return normalize_spaces(first_line(item.get("title") or ""))

def _fmt_chip_brand(item: dict) -> str:
    extra = item.get("extra") or {}
    return (
        f"{_fmt_title(item)} | sku={item.get('sku_hint')} | "
        f"chip_hint={extra.get('chip_hint')} | brand_hint={extra.get('brand_hint')}"
    )

def _fmt_vram_code(item: dict) -> str:
    extra = item.get("extra") or {}
    title = item.get("title") or ""
    match = _VRAM_CODE_RE.search(title)
    code = match.group(0) if match else ""
    return f"{_fmt_title(item)} | code={code} | vram_gb_hint={extra.get('vram_gb_hint')}"

def _fmt_model_dash(item: dict) -> str:
    extra = item.get("extra") or {}
    return f"{_fmt_title(item)} | product_model_hint={extra.get('product_model_hint')}"

def _gpu_required_lists(items: list[dict]) -> dict[str, list[dict]]:
    chip_brand_null = []
    vram_null_with_code = []
    model_dash_dash = []
    for d in items:
        extra = d.get("extra") or {}
        if extra.get("chip_hint") is None or extra.get("brand_hint") is None:
            chip_brand_null.append(d)
        if extra.get("vram_gb_hint") is None and _VRAM_CODE_RE.search(d.get("title") or ""):
            vram_null_with_code.append(d)
        product_model = extra.get("product_model_hint")
        if isinstance(product_model, str) and "- -" in product_model:
            model_dash_dash.append(d)
    return {
        "chip_brand_null": chip_brand_null,
        "vram_null_with_code": vram_null_with_code,
        "model_dash_dash": model_dash_dash,
    }

def _write_required_section(out: list[str], label: str, items: list[dict]) -> None:
    total = len(items)
    sku_null = sum(1 for d in items if d.get("sku_hint") is None)
    out.append(f"## {label}")
    out.append(f"items: {total}")
    out.append(f"sku_hint null: {_fmt_ratio(sku_null, total)}")
    out.append("extra null counts:")
    for field in _IMPORTANT_FIELDS:
        nulls, total = _count_field_nulls(items, field)
        out.append(f"  - {field}: {_fmt_ratio(nulls, total)}")


def _limit_samples(items: list[dict], limit: int) -> list[dict]:
    return items[:limit]


def _gpu_null_patterns(items: list[dict]) -> Counter[str]:
    patterns = Counter()
    for d in items:
        if d.get("sku_hint") is not None:
            continue
        line = first_line(d.get("title") or "")
        if _GPU_ACCESSORY_RE.search(line):
            patterns["accessory"] += 1
        elif re.search(r"(?i)RTX\\s*PRO", line):
            patterns["rtx_pro"] += 1
        elif re.search(r"(?i)RTX\\s*A\\d", line):
            patterns["rtx_a"] += 1
        elif re.search(r"(?i)(?<![A-Za-z0-9])(GT\\s*\\d{3,4}|N\\d{3})", line):
            patterns["legacy_gt"] += 1
        elif re.search(r"(?i)\\bRTX\\b", line):
            patterns["rtx_other"] += 1
        elif re.search(r"(?i)\\bRX\\b", line):
            patterns["rx_other"] += 1
        elif re.search(r"(?i)\\bARC\\b", line):
            patterns["arc_other"] += 1
        else:
            patterns["unknown"] += 1
    return patterns


def _mb_null_patterns(items: list[dict]) -> Counter[str]:
    patterns = Counter()
    for d in items:
        if d.get("sku_hint") is not None:
            continue
        line = first_line(d.get("title") or "")
        head = head_before_brackets(line)
        if "+" in head or _MB_BUNDLE_RE.search(head):
            patterns["bundle"] += 1
        elif "/M.2" in head:
            patterns["m2_trunc"] += 1
        else:
            patterns["unknown"] += 1
    return patterns


def _cpu_null_patterns(items: list[dict]) -> Counter[str]:
    patterns = Counter()
    for d in items:
        if d.get("sku_hint") is not None:
            continue
        line = first_line(d.get("title") or "")
        if _CPU_ACCESSORY_RE.search(line):
            patterns["accessory"] += 1
        elif _CPU_KEYWORD_RE.search(line):
            patterns["cpu_like_missing"] += 1
        else:
            patterns["unknown"] += 1
    return patterns


def _summarize_cpu(items: list[dict]) -> dict:
    return {
        "total": len(items),
        "sku_null": _null_ratio(items),
        "extra_keys": {
            "brand_hint": _null_ratio(items, "brand_hint"),
            "model_hint": _null_ratio(items, "model_hint"),
            "is_bundle": _null_ratio(items, "is_bundle"),
            "is_accessory": _null_ratio(items, "is_accessory"),
        },
        "brand_missing": _limit_samples(
            [d for d in items if d.get("sku_hint") and (d.get("extra") or {}).get("brand_hint") is None],
            50,
        ),
        "null_samples": _limit_samples([d for d in items if d.get("sku_hint") is None], 50),
        "patterns": _cpu_null_patterns(items),
    }


def _summarize_mb(items: list[dict]) -> dict:
    bundle_hits = []
    m2_trunc = []
    for d in items:
        line = first_line(d.get("title") or "")
        head = head_before_brackets(line)
        if "+" in head or _MB_BUNDLE_RE.search(head):
            bundle_hits.append(d)
        if "/M.2" in head:
            sku = d.get("sku_hint") or ""
            if "/M.2" not in sku:
                m2_trunc.append(d)

    return {
        "total": len(items),
        "sku_null": _null_ratio(items),
        "extra_keys": {
            "chipset_hint": _null_ratio(items, "chipset_hint"),
            "variant_hint": _null_ratio(items, "variant_hint"),
            "is_bundle": _null_ratio(items, "is_bundle"),
        },
        "bundle_hits": _limit_samples(bundle_hits, 50),
        "m2_trunc": _limit_samples(m2_trunc, 50),
        "null_samples": _limit_samples([d for d in items if d.get("sku_hint") is None], 50),
        "patterns": _mb_null_patterns(items),
    }


def _summarize_gpu(items: list[dict]) -> dict:
    accessory_leaks = []
    vram_missing = []
    core_line_missing = []
    for d in items:
        title = d.get("title") or ""
        line = first_line(title)
        extra = d.get("extra") or {}
        if _GPU_ACCESSORY_RE.search(title) and not extra.get("is_accessory"):
            accessory_leaks.append(d)
        if _VRAM_RE.search(title) and extra.get("vram_gb_hint") is None:
            vram_missing.append(d)
        if d.get("sku_hint") is None:
            for l in title.splitlines():
                if "繪圖核心" in l or "GPU核心" in l or "Graphics" in l:
                    core_line_missing.append(d)
                    break

    return {
        "total": len(items),
        "sku_null": _null_ratio(items),
        "extra_keys": {
            "brand_hint": _null_ratio(items, "brand_hint"),
            "chip_hint": _null_ratio(items, "chip_hint"),
            "vram_gb_hint": _null_ratio(items, "vram_gb_hint"),
            "aib_hint": _null_ratio(items, "aib_hint"),
            "product_model_hint": _null_ratio(items, "product_model_hint"),
            "is_bundle": _null_ratio(items, "is_bundle"),
            "is_accessory": _null_ratio(items, "is_accessory"),
        },
        "accessory_leaks": _limit_samples(accessory_leaks, 50),
        "vram_missing": _limit_samples(vram_missing, 50),
        "core_line_missing": _limit_samples(core_line_missing, 50),
        "null_samples": _limit_samples([d for d in items if d.get("sku_hint") is None], 50),
        "patterns": _gpu_null_patterns(items),
    }


def _format_samples(items: list[dict]) -> str:
    lines = []
    for d in items:
        title = normalize_spaces(first_line(d.get("title") or ""))
        url = d.get("url") or ""
        sku = d.get("sku_hint")
        extra = d.get("extra")
        lines.append(f"- {title} | sku={sku} | url={url} | extra={extra}")
    return "\n".join(lines) if lines else "- (none)"


def _format_patterns(counter: Counter[str], strategies: dict[str, str]) -> str:
    if not counter:
        return "- (none)"
    lines = []
    for key, count in counter.most_common():
        strategy = strategies.get(key, "(no strategy)")
        lines.append(f"- {key}: {count} -> {strategy}")
    return "\n".join(lines)


def _write_section(out: list[str], label: str, summary: dict, strategies: dict[str, str]) -> None:
    out.append(f"## {label}")
    out.append(f"items: {summary['total']}")
    nulls, total = summary["sku_null"]
    out.append(f"sku_hint null: {_fmt_ratio(nulls, total)}")
    out.append("extra null ratios:")
    for key, (n, t) in summary["extra_keys"].items():
        out.append(f"  - {key}: {_fmt_ratio(n, t)}")
    out.append("top null patterns:")
    out.append(_format_patterns(summary["patterns"], strategies))
    out.append("null samples:")
    out.append(_format_samples(summary["null_samples"]))


def generate_report(before_dir: Path | None, after_dir: Path, out_path: Path) -> None:
    def _load_set(base: Path) -> dict[str, list[dict]]:
        return {
            "cpu": _load_items(base / "cpu.json"),
            "mb": _load_items(base / "mb.json"),
            "gpu": _load_items(base / "gpu.json"),
        }

    before = _load_set(before_dir) if before_dir else None
    after = _load_set(after_dir)

    strategies = {
        "accessory": "skip accessory/promo items or tighten accessory keywords",
        "cpu_like_missing": "expand CPU regex and ASCII boundaries for model detection",
        "bundle": "detect bundle keywords on head (before brackets) and skip output",
        "m2_trunc": "avoid splitting on '/', keep /M.2 tokens in sku_hint",
        "legacy_gt": "support GT1030 and N210/N710/N730 legacy naming",
        "rtx_a": "support RTX A-series patterns",
        "rtx_pro": "support RTX PRO workstation patterns",
        "rtx_other": "extend RTX variants based on data misses",
        "rx_other": "extend RX variants based on data misses",
        "arc_other": "extend ARC variants based on data misses",
        "unknown": "inspect samples to add minimal new rules",
    }

    out: list[str] = []
    out.append("CoolPC Parse Review Report")
    out.append(f"generated_at_utc: {datetime.now(timezone.utc).isoformat()}")
    out.append(f"before_dir: {before_dir}" if before_dir else "before_dir: (none)")
    out.append(f"after_dir: {after_dir}")
    out.append("")

    out.append("# REQUIRED CHECKS (AFTER)")
    _write_required_section(out, "CPU", after["cpu"])
    _write_required_section(out, "MB", after["mb"])
    _write_required_section(out, "GPU", after["gpu"])
    gpu_required = _gpu_required_lists(after["gpu"])
    out.append("GPU chip/brand null:")
    out.append(_format_issue_lines(gpu_required["chip_brand_null"], _fmt_chip_brand))
    out.append("GPU vram null but has code:")
    out.append(_format_issue_lines(gpu_required["vram_null_with_code"], _fmt_vram_code))
    out.append("GPU product_model_hint has '- -':")
    out.append(_format_issue_lines(gpu_required["model_dash_dash"], _fmt_model_dash))
    out.append("")

    if before:
        out.append("# BEFORE")
        _write_section(out, "CPU", _summarize_cpu(before["cpu"]), strategies)
        out.append("brand_missing samples:")
        out.append(_format_samples(_summarize_cpu(before["cpu"])["brand_missing"]))
        out.append("")
        _write_section(out, "MB", _summarize_mb(before["mb"]), strategies)
        out.append("bundle_hits:")
        out.append(_format_samples(_summarize_mb(before["mb"])["bundle_hits"]))
        out.append("m2_trunc:")
        out.append(_format_samples(_summarize_mb(before["mb"])["m2_trunc"]))
        out.append("")
        _write_section(out, "GPU", _summarize_gpu(before["gpu"]), strategies)
        out.append("accessory_leaks:")
        out.append(_format_samples(_summarize_gpu(before["gpu"])["accessory_leaks"]))
        out.append("vram_missing:")
        out.append(_format_samples(_summarize_gpu(before["gpu"])["vram_missing"]))
        out.append("core_line_missing:")
        out.append(_format_samples(_summarize_gpu(before["gpu"])["core_line_missing"]))
        out.append("")

    out.append("# AFTER")
    cpu_after = _summarize_cpu(after["cpu"])
    mb_after = _summarize_mb(after["mb"])
    gpu_after = _summarize_gpu(after["gpu"])
    _write_section(out, "CPU", cpu_after, strategies)
    out.append("brand_missing samples:")
    out.append(_format_samples(cpu_after["brand_missing"]))
    out.append("")
    _write_section(out, "MB", mb_after, strategies)
    out.append("bundle_hits:")
    out.append(_format_samples(mb_after["bundle_hits"]))
    out.append("m2_trunc:")
    out.append(_format_samples(mb_after["m2_trunc"]))
    out.append("")
    _write_section(out, "GPU", gpu_after, strategies)
    out.append("accessory_leaks:")
    out.append(_format_samples(gpu_after["accessory_leaks"]))
    out.append("vram_missing:")
    out.append(_format_samples(gpu_after["vram_missing"]))
    out.append("core_line_missing:")
    out.append(_format_samples(gpu_after["core_line_missing"]))

    out_path.write_text("\n".join(out) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--after-dir", default="temp", help="解析後的輸出資料夾（含 cpu.json/mb.json/gpu.json）")
    ap.add_argument("--before-dir", default=None, help="可選：修正前的輸出資料夾（含 cpu.json/mb.json/gpu.json）")
    ap.add_argument("--out", default="temp/review_report.txt", help="輸出報告檔案路徑")
    args = ap.parse_args()

    after_dir = Path(args.after_dir)
    before_dir = Path(args.before_dir) if args.before_dir else None
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    generate_report(before_dir, after_dir, out_path)
    print(f"OK: wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
