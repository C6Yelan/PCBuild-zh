#!/usr/bin/env bash
set -euo pipefail
umask 077

PROJECT_DIR="$HOME/Side Project/PCBuild-zh"
DB_SERVICE="pcbuild-db"
BACKUP_ROOT="/opt/pcbuild-backups/local"
PG_DIR="$BACKUP_ROOT/pg"
CFG_DIR="$BACKUP_ROOT/configs"
CACHE_HOST="/opt/pcbuild-backups/cache"

TS=$(date -u +"%Y%m%dT%H%M%SZ")

mkdir -p "$PG_DIR" "$CFG_DIR" "$CACHE_HOST"
chmod 700 "$CACHE_HOST"

cd "$PROJECT_DIR"

# 1) DB globals (roles/tablespaces/etc.)
docker compose exec -T "$DB_SERVICE" sh -lc \
  'export PGPASSWORD="$POSTGRES_PASSWORD"; pg_dumpall --globals-only -U "$POSTGRES_USER"' \
  > "${PG_DIR}/globals_${TS}.sql"

# 2) DB dump (custom format; for pg_restore)
docker compose exec -T "$DB_SERVICE" sh -lc \
  'export PGPASSWORD="$POSTGRES_PASSWORD"; pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB"' \
  > "${PG_DIR}/db_${TS}.dump"

# 3) Project configs (compose/env)
cfg_files=()
for f in docker-compose.yml docker-compose.yaml compose.yml compose.yaml \
         docker-compose.override.yml docker-compose.override.yaml \
         .env .env.* ; do
  [[ -e "$f" ]] && cfg_files+=("$f")
done
((${#cfg_files[@]})) && tar -czf "${CFG_DIR}/project_configs_${TS}.tar.gz" "${cfg_files[@]}"

# 4) cloudflared folder (if exists in repo)
[[ -d "cloudflared" ]] && tar -czf "${CFG_DIR}/cloudflared_${TS}.tar.gz" cloudflared

# 5) Lock down file perms
chmod 600 "${PG_DIR}/globals_${TS}.sql" "${PG_DIR}/db_${TS}.dump"
[[ -f "${CFG_DIR}/project_configs_${TS}.tar.gz" ]] && chmod 600 "${CFG_DIR}/project_configs_${TS}.tar.gz"
[[ -f "${CFG_DIR}/cloudflared_${TS}.tar.gz" ]] && chmod 600 "${CFG_DIR}/cloudflared_${TS}.tar.gz"

# 6) Encrypted snapshot into restic repo
docker run --rm --user "$(id -u):$(id -g)" \
  --env-file /opt/pcbuild-backups/restic.env \
  -v /opt/pcbuild-backups:/data \
  -v /opt/pcbuild-backups/cache:/cache \
  restic/restic --cache-dir /cache \
  backup --host pcbuild-prod --group-by paths /data/local

docker run --rm --user "$(id -u):$(id -g)" \
  --env-file /opt/pcbuild-backups/restic.env \
  -v /opt/pcbuild-backups:/data \
  -v /opt/pcbuild-backups/cache:/cache \
  restic/restic --cache-dir /cache \
  snapshots

# 7) Local cleanup (staging only)
# restic snapshots 有 retention，但 /opt/pcbuild-backups/local 需要自行清理避免膨脹
/opt/pcbuild-backups/bin/cleanup_local.sh
