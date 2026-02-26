#!/usr/bin/env bash
set -euo pipefail
umask 077

LOCAL_ROOT="/opt/pcbuild-backups/local"
PG_DIR="${LOCAL_ROOT}/pg"
CFG_DIR="${LOCAL_ROOT}/configs"

KEEP_PG_DAYS="${KEEP_PG_DAYS:-7}"
KEEP_CFG_DAYS="${KEEP_CFG_DAYS:-30}"

echo "[cleanup] start $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "[cleanup] keep pg=${KEEP_PG_DAYS}d, configs=${KEEP_CFG_DAYS}d"

# 刪除過舊 DB dump / globals
if [[ -d "$PG_DIR" ]]; then
  find "$PG_DIR" -maxdepth 1 -type f \
    \( -name 'db_*.dump' -o -name 'globals_*.sql' \) \
    -mtime +"$KEEP_PG_DAYS" -print -delete || true
fi

# 刪除過舊 configs tarball
if [[ -d "$CFG_DIR" ]]; then
  find "$CFG_DIR" -maxdepth 1 -type f -name '*.tar.gz' \
    -mtime +"$KEEP_CFG_DAYS" -print -delete || true
fi

echo "[cleanup] done"
