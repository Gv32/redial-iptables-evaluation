#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

BACKUP="$(find "$PWD/runs" -name fw1.backup.rules | sort | tail -1)"

if [ -z "$BACKUP" ]; then
  echo "[ERR] nessun fw1.backup.rules trovato in runs/"
  exit 1
fi

export WORKDIR="$(dirname "$BACKUP")"

echo "[pre-last] uso WORKDIR=$WORKDIR"
./start.sh pre
