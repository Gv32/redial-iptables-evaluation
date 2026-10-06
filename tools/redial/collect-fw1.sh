#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
source ./lib.sh

echo "[collect] salvo ruleset originale FW1"

fw1_sudo "ip netns exec $FW1_NETNS iptables-save" \
  > "$WORKDIR/fw1.backup.rules"

echo "[collect] scritto: $WORKDIR/fw1.backup.rules"

echo "[collect] converto in XML"

command -v iptables-xml >/dev/null 2>&1 || die "iptables-xml non trovato"

iptables-xml < "$WORKDIR/fw1.backup.rules" > "$WORKDIR/fw1.xml"

echo "[collect] scritto: $WORKDIR/fw1.xml"

echo "[collect] OK"
ls -lh "$WORKDIR/fw1.backup.rules" "$WORKDIR/fw1.xml"
