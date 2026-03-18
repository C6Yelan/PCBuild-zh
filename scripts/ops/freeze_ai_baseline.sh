#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

COMPOSE=(docker compose)
FASTAPI_SERVICE="fastapi"
RUN_TS_UTC="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="/tmp/ai-baseline-freeze-${RUN_TS_UTC}"

usage() {
  cat <<'EOF'
Usage:
  scripts/ops/freeze_ai_baseline.sh

Description:
  Collect AI baseline fingerprint and existing ops check outputs into:
  /tmp/ai-baseline-freeze-<UTC timestamp>/
EOF
}

print_section() {
  printf '\n== %s ==\n' "$1"
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "$cmd" >&2
    exit 1
  fi
}

read_fastapi_env() {
  local name="$1"
  case "$name" in
    AI_PROVIDER)
      "${COMPOSE[@]}" exec -T "$FASTAPI_SERVICE" sh -lc 'printf "%s" "${AI_PROVIDER:-}"'
      ;;
    AI_MODEL)
      "${COMPOSE[@]}" exec -T "$FASTAPI_SERVICE" sh -lc 'printf "%s" "${AI_MODEL:-}"'
      ;;
    AI_TIMEOUT_SECONDS)
      "${COMPOSE[@]}" exec -T "$FASTAPI_SERVICE" sh -lc 'printf "%s" "${AI_TIMEOUT_SECONDS:-}"'
      ;;
    AI_MAX_OUTPUT_CHARS)
      "${COMPOSE[@]}" exec -T "$FASTAPI_SERVICE" sh -lc 'printf "%s" "${AI_MAX_OUTPUT_CHARS:-}"'
      ;;
    *)
      printf 'Unsupported env key: %s\n' "$name" >&2
      exit 1
      ;;
  esac
}

read_base_url_sha12() {
  "${COMPOSE[@]}" exec -T "$FASTAPI_SERVICE" sh -lc '
if [ -z "${AI_OAI_BASE_URL:-}" ]; then
  printf "%s" "-"
  exit 0
fi
if command -v sha256sum >/dev/null 2>&1; then
  printf "%s" "${AI_OAI_BASE_URL}" | sha256sum | cut -c1-12
  exit 0
fi
if command -v shasum >/dev/null 2>&1; then
  printf "%s" "${AI_OAI_BASE_URL}" | shasum -a 256 | cut -c1-12
  exit 0
fi
printf "%s\n" "Missing sha256 tool in fastapi container." >&2
exit 1
'
}

extract_json_string() {
  local key="$1"
  local path="$2"
  local line
  local value

  if [[ ! -f "$path" ]]; then
    printf '%s' '-'
    return 0
  fi

  line="$(grep -m1 "\"${key}\"" "$path" || true)"
  if [[ -z "$line" ]]; then
    printf '%s' '-'
    return 0
  fi

  value="$(printf '%s\n' "$line" | sed -En 's/^[[:space:]]*"[^"]+"[[:space:]]*:[[:space:]]*"([^"]*)".*$/\1/p')"
  if [[ -z "$value" ]]; then
    printf '%s' '-'
    return 0
  fi

  printf '%s' "$value"
}

run_python_module() {
  local label="$1"
  shift

  local stdout_path="$OUT_DIR/${label}.stdout.json"
  local stderr_path="$OUT_DIR/${label}.stderr.log"
  local status_path="$OUT_DIR/${label}.exit_code"
  local status

  print_section "$label"
  printf 'command=docker compose exec -T %s python -m %s\n' "$FASTAPI_SERVICE" "$*"

  set +e
  "${COMPOSE[@]}" exec -T "$FASTAPI_SERVICE" python -m "$@" >"$stdout_path" 2>"$stderr_path"
  status=$?
  set -e

  printf '%s\n' "$status" >"$status_path"

  if [[ -s "$stdout_path" ]]; then
    cat "$stdout_path"
    printf '\n'
  else
    printf '(no stdout captured)\n'
  fi

  if [[ -s "$stderr_path" ]]; then
    printf 'stderr_path=%s\n' "$stderr_path"
  fi
  printf 'exit_code=%s\n' "$status"

  RUN_MODULE_STATUS="$status"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_cmd git
require_cmd docker
require_cmd date
require_cmd grep
require_cmd sed

cd "$REPO_ROOT"

if ! "${COMPOSE[@]}" ps >/dev/null 2>&1; then
  printf 'docker compose is not available in %s\n' "$REPO_ROOT" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

git_sha="$(git rev-parse HEAD)"
ai_provider="$(read_fastapi_env AI_PROVIDER)"
ai_model="$(read_fastapi_env AI_MODEL)"
ai_timeout_seconds="$(read_fastapi_env AI_TIMEOUT_SECONDS)"
ai_max_output_chars="$(read_fastapi_env AI_MAX_OUTPUT_CHARS)"
ai_oai_base_url_sha12="$(read_base_url_sha12)"

cat >"$OUT_DIR/commands.txt" <<'EOF'
docker compose exec -T fastapi python -m backend.tools.ops.chat_provider_healthcheck
docker compose exec -T fastapi python -m backend.tools.ops.chat_regression_report
docker compose exec -T fastapi python -m backend.tools.ops.chat_release_check --mode p10
EOF

cat >"$OUT_DIR/ai_fingerprint.txt" <<EOF
generated_at_utc=${RUN_TS_UTC}
git_sha=${git_sha}
AI_PROVIDER=${ai_provider}
AI_MODEL=${ai_model}
AI_TIMEOUT_SECONDS=${ai_timeout_seconds}
AI_MAX_OUTPUT_CHARS=${ai_max_output_chars}
AI_OAI_BASE_URL_SHA12=${ai_oai_base_url_sha12}
EOF

print_section "AI Baseline Fingerprint"
cat "$OUT_DIR/ai_fingerprint.txt"

run_python_module "provider_healthcheck" backend.tools.ops.chat_provider_healthcheck
provider_status="$RUN_MODULE_STATUS"

run_python_module "chat_regression_report" backend.tools.ops.chat_regression_report
regression_status="$RUN_MODULE_STATUS"

run_python_module "chat_release_acceptance" backend.tools.ops.chat_release_check --mode p10
release_status="$RUN_MODULE_STATUS"

provider_report_path="$(extract_json_string report_path "$OUT_DIR/provider_healthcheck.stdout.json")"
regression_report_path="$(extract_json_string report_path "$OUT_DIR/chat_regression_report.stdout.json")"
release_snapshot_root="$(extract_json_string snapshot_root "$OUT_DIR/chat_release_acceptance.stdout.json")"

cat >"$OUT_DIR/baseline_summary.txt" <<EOF
generated_at_utc=${RUN_TS_UTC}
git_sha=${git_sha}
AI_PROVIDER=${ai_provider}
AI_MODEL=${ai_model}
AI_TIMEOUT_SECONDS=${ai_timeout_seconds}
AI_MAX_OUTPUT_CHARS=${ai_max_output_chars}
AI_OAI_BASE_URL_SHA12=${ai_oai_base_url_sha12}
provider_healthcheck_exit_code=${provider_status}
provider_healthcheck_report_path=${provider_report_path}
chat_regression_report_exit_code=${regression_status}
chat_regression_report_path=${regression_report_path}
chat_release_acceptance_exit_code=${release_status}
chat_release_acceptance_snapshot_root=${release_snapshot_root}
EOF

overall_status=0
if [[ "$provider_status" -ne 0 || "$regression_status" -ne 0 || "$release_status" -ne 0 ]]; then
  overall_status=2
fi

print_section "Summary"
cat "$OUT_DIR/baseline_summary.txt"

printf '\n輸出目錄：%s\n' "$OUT_DIR"
printf '下一步：請手動打一筆真實 chat request 並記錄 request_id。\n'

exit "$overall_status"
