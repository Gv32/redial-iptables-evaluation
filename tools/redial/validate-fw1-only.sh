#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
source ./lib.sh

RULES="$WORKDIR/fw1.redial-only.rules"

[ -f "$RULES" ] || die "manca $RULES; esegui prima generate"

echo "[validate] copio ruleset su FW1"
fw1_put "$RULES" /tmp/fw1.redial-only.rules

echo "[validate] iptables-restore --test"
fw1_sudo "ip netns exec $FW1_NETNS iptables-restore --test /tmp/fw1.redial-only.rules"

echo "[validate] OK"
