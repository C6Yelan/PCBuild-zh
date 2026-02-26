#!/usr/bin/env bash
set -euo pipefail
umask 077

docker run --rm --user "$(id -u):$(id -g)" \
  --env-file /opt/pcbuild-backups/restic.env \
  -v /opt/pcbuild-backups:/data \
  -v /opt/pcbuild-backups/cache:/cache \
  restic/restic --cache-dir /cache \
  forget --group-by paths \
  --keep-daily 7 --keep-weekly 4 --keep-monthly 6 \
  --prune

docker run --rm --user "$(id -u):$(id -g)" \
  --env-file /opt/pcbuild-backups/restic.env \
  -v /opt/pcbuild-backups:/data \
  -v /opt/pcbuild-backups/cache:/cache \
  restic/restic --cache-dir /cache \
  snapshots
