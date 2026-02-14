from __future__ import annotations

import argparse
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

    stages = _build_stages(
        python_executable=sys.executable,
        input_path=args.input,
        registry_path=args.registry,
        plans_path=plans_path,
        candidates_path=candidates_path,
        gated_candidates_path=gated_candidates_path,
        evidence_path=evidence_path,
        decisions_path=decisions_path,
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
            ],
        ),
    ]


def _print_stage_command(stage: _PipelineStage) -> None:
    print(f"[{stage.name}] {shlex.join(stage.cmd)}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
