from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class _PipelineStage:
    name: str
    cmd: list[str]


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir: Path = args.run_dir
    run_dir.mkdir(parents=True, exist_ok=True)

    plans_path = run_dir / "plans.json"
    candidates_path = run_dir / "candidates.jsonl"
    gated_candidates_path = run_dir / "gated_candidates.jsonl"
    evidence_path = run_dir / "evidence.jsonl"
    decisions_path = run_dir / "decisions.jsonl"
    plan_report_path = run_dir / "discovery_plan_report.json"
    plan_failure_map_path = run_dir / "plan_failure_reasons.json"

    stages = _build_stages(
        python_executable=sys.executable,
        input_path=args.input,
        registry_path=args.registry,
        plans_path=plans_path,
        candidates_path=candidates_path,
        gated_candidates_path=gated_candidates_path,
        evidence_path=evidence_path,
        decisions_path=decisions_path,
        plan_report_path=plan_report_path,
        plan_failure_map_path=plan_failure_map_path,
        topk=args.topk,
        min_accept_score=args.min_accept_score,
        timeout_seconds=args.timeout_seconds,
        max_bytes=args.max_bytes,
        user_agent_token=args.user_agent_token,
    )

    for stage in stages:
        _print_stage_command(stage)
        completed = subprocess.run(
            stage.cmd,
            check=False,
            shell=False,
            cwd=str(_project_root()),
        )
        if completed.returncode != 0:
            print(
                f"pipeline_failed phase={stage.name} returncode={completed.returncode}",
                file=sys.stderr,
            )
            return completed.returncode or 1
        if stage.name == "Phase B":
            plan_failure_map = _build_plan_failure_reason_by_plan_index(plan_report_path)
            _write_plan_failure_reason_map(plan_failure_map_path, plan_failure_map)

    print(f"pipeline_completed run_dir={run_dir}", file=sys.stderr)
    return 0


def _parse_args(argv: Optional[list[str]]) -> argparse.Namespace:
    project_root = _project_root()
    temp_root = (project_root / "temp").resolve()
    default_run_dir = temp_root / "t6_run"
    default_registry = (
        project_root
        / "backend"
        / "services"
        / "crawler"
        / "official_reconcile_gate"
        / "planning"
        / "data"
        / "official_registry.v1.json"
    )

    parser = argparse.ArgumentParser(prog="t6_run_official_reconcile_pipeline")
    parser.add_argument("--input", required=True, help="retail input JSON path")
    parser.add_argument("--run-dir", default=str(default_run_dir), help="pipeline output directory under temp/")
    parser.add_argument("--registry", default=str(default_registry), help="official registry path")
    parser.add_argument("--topk", type=int, default=5)
    parser.add_argument("--min-accept-score", type=int, default=3)
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    parser.add_argument("--max-bytes", type=int, default=131072)
    parser.add_argument("--user-agent-token", default="PCBuildBot")

    args = parser.parse_args(argv)

    args.input = _resolve_path(args.input, project_root)
    args.registry = _resolve_path(args.registry, project_root)
    args.run_dir = _resolve_path(args.run_dir, project_root)
    if not args.run_dir.is_relative_to(temp_root):
        parser.error("--run-dir must be under temp/")

    if args.topk <= 0:
        parser.error("--topk must be > 0")
    if args.min_accept_score < 0:
        parser.error("--min-accept-score must be >= 0")
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be > 0")
    if args.max_bytes <= 0:
        parser.error("--max-bytes must be > 0")

    return args


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _resolve_path(raw: str, project_root: Path) -> Path:
    path = Path(raw)
    if path.is_absolute():
        return path.resolve()
    return (project_root / path).resolve()


def _build_stages(
    *,
    python_executable: str,
    input_path: Path,
    registry_path: Path,
    plans_path: Path,
    candidates_path: Path,
    gated_candidates_path: Path,
    evidence_path: Path,
    decisions_path: Path,
    plan_report_path: Path,
    plan_failure_map_path: Path,
    topk: int,
    min_accept_score: int,
    timeout_seconds: float,
    max_bytes: int,
    user_agent_token: str,
) -> list[_PipelineStage]:
    return [
        _PipelineStage(
            name="Phase A",
            cmd=[
                python_executable,
                "-m",
                "backend.tools.crawler.t6_build_official_lookup_plan",
                "--input",
                str(input_path),
                "--output",
                str(plans_path),
                "--registry",
                str(registry_path),
            ],
        ),
        _PipelineStage(
            name="Phase B",
            cmd=[
                python_executable,
                "-m",
                "backend.tools.crawler.t6_discover_official_candidates",
                "--plans",
                str(plans_path),
                "--output",
                str(candidates_path),
                "--registry",
                str(registry_path),
                "--topk",
                str(topk),
                "--timeout-seconds",
                str(timeout_seconds),
                "--plan-report",
                str(plan_report_path),
            ],
        ),
        _PipelineStage(
            name="Phase C",
            cmd=[
                python_executable,
                "-m",
                "backend.tools.crawler.t6_robots_gate_candidates",
                "--candidates",
                str(candidates_path),
                "--output",
                str(gated_candidates_path),
                "--registry",
                str(registry_path),
                "--user-agent-token",
                str(user_agent_token),
            ],
        ),
        _PipelineStage(
            name="Phase D",
            cmd=[
                python_executable,
                "-m",
                "backend.tools.crawler.t6_fetch_candidate_evidence",
                "--input",
                str(gated_candidates_path),
                "--output",
                str(evidence_path),
                "--registry",
                str(registry_path),
                "--timeout-seconds",
                str(timeout_seconds),
                "--max-bytes",
                str(max_bytes),
            ],
        ),
        _PipelineStage(
            name="Phase E",
            cmd=[
                python_executable,
                "-m",
                "backend.tools.crawler.t6_score_official_candidates",
                "--plans",
                str(plans_path),
                "--gated-candidates",
                str(gated_candidates_path),
                "--evidence",
                str(evidence_path),
                "--output",
                str(decisions_path),
                "--topk",
                str(topk),
                "--min-accept-score",
                str(min_accept_score),
                "--plan-failure-map",
                str(plan_failure_map_path),
            ],
        ),
    ]


def _print_stage_command(stage: _PipelineStage) -> None:
    print(f"[{stage.name}] {shlex.join(stage.cmd)}", file=sys.stderr)


def _build_plan_failure_reason_by_plan_index(plan_report_path: Path) -> dict[str, str]:
    if not plan_report_path.exists():
        return {}
    try:
        payload = json.loads(plan_report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, list):
        return {}

    out: dict[str, str] = {}
    for row in payload:
        if not isinstance(row, dict):
            continue
        plan_index = row.get("plan_index")
        if not isinstance(plan_index, int):
            continue
        reason = _derive_plan_failure_reason(row)
        if reason:
            out[str(plan_index)] = reason
    return out


def _derive_plan_failure_reason(plan_report_row: dict[str, object]) -> str | None:
    candidates_emitted = plan_report_row.get("candidates_emitted")
    if isinstance(candidates_emitted, int) and candidates_emitted > 0:
        return None

    parsed_urlsets = plan_report_row.get("parsed_urlsets")
    parsed_indexes = plan_report_row.get("parsed_indexes")
    parsed_urlsets_int = parsed_urlsets if isinstance(parsed_urlsets, int) else 0
    parsed_indexes_int = parsed_indexes if isinstance(parsed_indexes, int) else 0

    errors = plan_report_row.get("errors")
    error_rows = errors if isinstance(errors, list) else []
    normalized_errors: list[dict[str, str]] = []
    for item in error_rows:
        if not isinstance(item, dict):
            continue
        reason_val = item.get("reason")
        detail_val = item.get("detail")
        reason = str(reason_val).strip() if isinstance(reason_val, str) else ""
        detail = str(detail_val).strip() if isinstance(detail_val, str) else ""
        if reason:
            normalized_errors.append({"reason": reason, "detail": detail})

    for item in normalized_errors:
        if item["reason"] == "blocked":
            detail = item["detail"] or "blocked"
            return f"discovery_blocked/{detail}"
    for item in normalized_errors:
        if item["reason"] == "no_sitemap_found":
            return "no_sitemap_found"
    for item in normalized_errors:
        if item["reason"] == "plan_skipped":
            detail = item["detail"] or "unknown"
            return f"plan_skipped/{detail}"
    if parsed_urlsets_int == 0 and parsed_indexes_int == 0:
        return "no_sitemap_found"
    if normalized_errors:
        first = normalized_errors[0]
        if first["detail"]:
            return f"{first['reason']}/{first['detail']}"
        return first["reason"]
    return None


def _write_plan_failure_reason_map(path: Path, mapping: dict[str, str]) -> None:
    payload = mapping if mapping else {}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
