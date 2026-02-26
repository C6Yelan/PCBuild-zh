#!/usr/bin/env bash
set -euo pipefail
umask 077

docker run --rm --user "$(id -u):$(id -g)" \
  --env-file /opt/pcbuild-backups/restic.env \
  -v /opt/pcbuild-backups:/data \
  -v /opt/pcbuild-backups/cache:/cache \
  restic/restic --cache-dir /cache \
  check
