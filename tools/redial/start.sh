#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

cmd="${1:-help}"

case "$cmd" in
  prepare)
    echo "[start] prepare = collect + generate + validate"
    ./collect-fw1.sh
    ./generate-fw1-only.sh
    ./validate-fw1-only.sh
    ;;

  post)
    echo "[start] post = applica FW1^ post-REDIAL-only"
    ./apply-fw1-only.sh
    ;;

  pre)
    echo "[start] pre = rollback al ruleset originale"
    ./rollback-fw1.sh
    ;;

  pre-last)
    echo "[start] pre-last = rollback usando l'ultima run con fw1.backup.rules"

    BACKUP="$(find "$PWD/runs" -name fw1.backup.rules | sort | tail -1 || true)"

    if [ -z "$BACKUP" ]; then
      echo "[ERR] nessun fw1.backup.rules trovato in $PWD/runs"
      exit 1
    fi

    export WORKDIR="$(dirname "$BACKUP")"

    echo "[start] uso WORKDIR=$WORKDIR"
    ./rollback-fw1.sh
    ;;

  status)
    ./status-fw1.sh
    ;;

  collect)
    ./collect-fw1.sh
    ;;

  generate)
    ./generate-fw1-only.sh
    ;;

  validate)
    ./validate-fw1-only.sh
    ;;

  apply)
    ./apply-fw1-only.sh
    ;;

  rollback)
    ./rollback-fw1.sh
    ;;

  help|*)
    cat <<USAGE
Uso:
  ./start.sh prepare    collect + generate + validate, non applica
  ./start.sh post       applica FW1^ post-REDIAL-only
  ./start.sh pre        ripristina FW1 originale usando la WORKDIR corrente
  ./start.sh pre-last   ripristina FW1 usando l'ultima run con backup valido
  ./start.sh status     mostra stato FW1

Comandi singoli:
  ./start.sh collect
  ./start.sh generate
  ./start.sh validate
  ./start.sh apply
  ./start.sh rollback

Flusso tipico:
  unset WORKDIR
  source ./inventory.sh
  ./start.sh prepare
  ./start.sh post

Rollback:
  ./start.sh pre-last

Oppure, rollback da una run specifica:
  export WORKDIR=/home/drago/redial-single-fw/runs/YYYYMMDD-HHMMSS
  ./start.sh pre
USAGE
    ;;
esac
