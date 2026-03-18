#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

SOURCE="coolpc"
ENV_NAME="prod"
HOURS=48
PUBLICATION_LIMIT=10
SUSPICIOUS_LIMIT=30

cd "$REPO_ROOT"

COMPOSE=(docker compose)

usage() {
  cat <<'EOF'
Usage:
  scripts/ops/check_crawler_health.sh [options]

Options:
  --source <id>              crawler source, default: coolpc
  --env <name>               publication env, default: prod
  --hours <n>                lookback window in hours, default: 48
  --publication-limit <n>    publications to show, default: 10
  --suspicious-limit <n>     suspicious log lines to show per section, default: 30
  -h, --help                 show this help

Examples:
  scripts/ops/check_crawler_health.sh
  scripts/ops/check_crawler_health.sh --hours 72
  scripts/ops/check_crawler_health.sh --source coolpc --env prod
EOF
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "$cmd" >&2
    exit 1
  fi
}

print_section() {
  printf '\n== %s ==\n' "$1"
}

count_matches() {
  local pattern="$1"
  local text="$2"
  local count
  count="$(printf '%s\n' "$text" | grep -E -c "$pattern" || true)"
  printf '%s' "$count"
}

show_matches() {
  local pattern="$1"
  local text="$2"
  local limit="$3"
  local matches

  matches="$(printf '%s\n' "$text" | grep -E "$pattern" || true)"
  if [[ -z "$matches" ]]; then
    printf '(none)\n'
    return 0
  fi

  printf '%s\n' "$matches" | tail -n "$limit"
}

sql_escape() {
  printf "%s" "$1" | sed "s/'/''/g"
}

run_psql() {
  local sql="$1"
  "${COMPOSE[@]}" exec -T pcbuild-db sh -lc \
    'export PGPASSWORD="$POSTGRES_PASSWORD"; psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -P pager=off' \
    <<<"$sql"
}

latest_summary_path() {
  find temp/t10 -type f -name summary.json -printf '%T@ %p\n' 2>/dev/null \
    | sort -nr \
    | head -n 1 \
    | cut -d' ' -f2-
}

extract_last_json_line() {
  local text="$1"
  printf '%s\n' "$text" | awk '/^\{.*\}$/ { line = $0 } END { print line }'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)
      SOURCE="${2:?missing value for --source}"
      shift 2
      ;;
    --env)
      ENV_NAME="${2:?missing value for --env}"
      shift 2
      ;;
    --hours)
      HOURS="${2:?missing value for --hours}"
      shift 2
      ;;
    --publication-limit)
      PUBLICATION_LIMIT="${2:?missing value for --publication-limit}"
      shift 2
      ;;
    --suspicious-limit)
      SUSPICIOUS_LIMIT="${2:?missing value for --suspicious-limit}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

require_cmd docker
require_cmd awk
require_cmd cut
require_cmd grep
require_cmd find
require_cmd sed
require_cmd sort
require_cmd tail

HAS_JQ=0
if command -v jq >/dev/null 2>&1; then
  HAS_JQ=1
fi

if ! "${COMPOSE[@]}" ps >/dev/null 2>&1; then
  printf 'docker compose is not available in %s\n' "$REPO_ROOT" >&2
  exit 1
fi

SOURCE_SQL="$(sql_escape "$SOURCE")"
ENV_SQL="$(sql_escape "$ENV_NAME")"

print_section "Context"
printf 'repo=%s\n' "$REPO_ROOT"
printf 'source=%s env=%s lookback_hours=%s\n' "$SOURCE" "$ENV_NAME" "$HOURS"

print_section "Recent Publications"
if publications_output="$("${COMPOSE[@]}" exec -T fastapi python -m backend.tools.ops.list_publications --limit "$PUBLICATION_LIMIT" --env "$ENV_NAME" 2>&1)"; then
  publications_json="$(extract_last_json_line "$publications_output")"
  if [[ "$HAS_JQ" -eq 1 && -n "$publications_json" ]]; then
    printf '%s\n' "$publications_json" | jq '{
      pointers,
      publications: [
        .publications[]
        | {
            published_at,
            run_id,
            note,
            stats
          }
      ]
    }'
  else
    printf '%s\n' "$publications_output"
  fi
else
  printf '%s\n' "$publications_output"
fi

scheduler_logs="$("${COMPOSE[@]}" logs --since="${HOURS}h" pcbuild-scheduler 2>&1 || true)"
pipeline_logs="$("${COMPOSE[@]}" logs --since="${HOURS}h" pcbuild-scheduler fastapi 2>&1 || true)"

tick_done="$(count_matches 'event=t10_scheduler_tick_done' "$scheduler_logs")"
tick_failed="$(count_matches 'event=t10_scheduler_tick_failed' "$scheduler_logs")"
tick_locked="$(count_matches 'event=t10_scheduler_tick_skipped_locked' "$scheduler_logs")"
no_change="$(count_matches 'event=t10_no_change' "$pipeline_logs")"
fetch_errors="$(count_matches 'event=t10_fetch.*status=error' "$pipeline_logs")"
fetch_http_block="$(count_matches 'event=t10_fetch.*status_code=(403|429|503)' "$pipeline_logs")"
robots_block="$(count_matches 'Blocked by robots\.txt' "$pipeline_logs")"
stage_fail="$(count_matches 'event=t10_stage_done.*rc=[1-9][0-9]*' "$pipeline_logs")"
gate_fail="$(count_matches 'event=gate_result.*status=fail' "$pipeline_logs")"
publish_done="$(count_matches 'event=t9_publish_finished.*published=true' "$pipeline_logs")"
publish_fail="$(count_matches 'event=t9_publish_failed' "$pipeline_logs")"
publish_skipped_no_change="$(count_matches 'event=t10_publish_done.*reason=skipped_no_changed_parts' "$pipeline_logs")"

print_section "Scheduler Signal Counts"
printf 'tick_done=%s\n' "$tick_done"
printf 'tick_failed=%s\n' "$tick_failed"
printf 'tick_skipped_locked=%s\n' "$tick_locked"
printf 't10_no_change=%s\n' "$no_change"
printf 'fetch_errors=%s\n' "$fetch_errors"
printf 'fetch_http_403_429_503=%s\n' "$fetch_http_block"
printf 'robots_block=%s\n' "$robots_block"
printf 'stage_fail=%s\n' "$stage_fail"
printf 'gate_fail=%s\n' "$gate_fail"
printf 'publish_done_true=%s\n' "$publish_done"
printf 'publish_fail=%s\n' "$publish_fail"
printf 'publish_skipped_no_changed_parts=%s\n' "$publish_skipped_no_change"

print_section "Suspicious Log Lines"
show_matches 'event=t10_fetch.*status=error|event=t10_fetch.*status_code=(403|429|503)|Blocked by robots\.txt|event=t10_stage_done.*rc=[1-9][0-9]*|event=gate_result.*status=fail|event=t9_publish_failed' "$pipeline_logs" "$SUSPICIOUS_LIMIT"

print_section "Recent No-change Lines"
show_matches 'event=t10_no_change|event=t10_publish_done.*reason=skipped_no_changed_parts' "$pipeline_logs" "$SUSPICIOUS_LIMIT"

print_section "Fetch State"
run_psql "
select
  source,
  part_type,
  last_status_code,
  to_char(last_success_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI:SS') as last_success_at_utc,
  to_char(updated_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI:SS') as updated_at_utc
from crawler_fetch_state
where source = '${SOURCE_SQL}'
order by updated_at desc;
"

print_section "Recent Ingest Runs"
run_psql "
select
  to_char(r.created_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI:SS') as created_at_utc,
  r.run_id,
  case when p.run_id is null then false else true end as published
from crawler_ingest_run r
left join crawler_publication p on p.run_id = r.run_id
where r.source = '${SOURCE_SQL}'
order by r.created_at desc
limit 20;
"

print_section "Recent Gate Fail Rows"
run_psql "
select
  to_char(created_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI:SS') as created_at_utc,
  run_id,
  gate_name,
  item_key
from crawler_stg_gate_result
where status = 'fail'
  and created_at > now() - interval '${HOURS} hours'
order by created_at desc
limit 50;
"

print_section "Publication Pointer"
run_psql "
select
  env,
  run_id,
  to_char(updated_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI:SS') as updated_at_utc
from crawler_publication_pointer
where env = '${ENV_SQL}';
"

print_section "Latest Incremental Summary"
latest_summary="$(latest_summary_path || true)"
if [[ -n "${latest_summary:-}" && -f "$latest_summary" ]]; then
  printf 'path=%s\n' "$latest_summary"
  if [[ "$HAS_JQ" -eq 1 ]]; then
    jq '{
      run_id,
      started_at,
      ended_at,
      exit_code,
      counts,
      merge,
      publish,
      errors,
      parts: [
        .parts[]
        | {
            part_type,
            status,
            skip_reason,
            fetch_status: (.fetch.status_code // null),
            stage_rc: (.stage.rc // null)
          }
      ]
    }' "$latest_summary"
  else
    cat "$latest_summary"
  fi
else
  printf 'No incremental summary.json found under temp/t10.\n'
fi

print_section "Diagnosis Hint"
if [[ "$tick_done" -eq 0 ]]; then
  printf 'Scheduler did not produce any completed tick in the last %s hours. Check pcbuild-scheduler container health first.\n' "$HOURS"
elif [[ "$fetch_errors" -gt 0 || "$fetch_http_block" -gt 0 || "$robots_block" -gt 0 ]]; then
  printf 'Fetch layer shows hard failures or block-like HTTP statuses. This is closer to blocked/upstream error than normal no-update.\n'
elif [[ "$stage_fail" -gt 0 || "$gate_fail" -gt 0 || "$publish_fail" -gt 0 ]]; then
  printf 'Fetch likely succeeded at least once, but parse/gate/publish failed later in the pipeline.\n'
elif [[ "$no_change" -gt 0 && "$publish_done" -eq 0 ]]; then
  printf 'Recent runs look like no-change detection. This is more consistent with upstream not changing than crawler being blocked.\n'
else
  printf 'No single dominant signal. Check the suspicious log lines and latest summary together.\n'
fi
