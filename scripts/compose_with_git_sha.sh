#!/usr/bin/env bash
set -euo pipefail

if [ -z "${APP_GIT_SHA:-}" ]; then
  APP_GIT_SHA="$(git rev-parse --short=12 HEAD)"
fi

export APP_GIT_SHA
echo "APP_GIT_SHA=${APP_GIT_SHA}"

exec docker compose "$@"
