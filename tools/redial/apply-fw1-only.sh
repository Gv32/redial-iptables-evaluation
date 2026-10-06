#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
source ./lib.sh

RULES="$WORKDIR/fw1.redial-only.rules"

[ -f "$RULES" ] || die "manca $RULES; esegui prima generate"

echo "[apply] copio ruleset su FW1"
fw1_put "$RULES" /tmp/fw1.redial-only.rules

echo "[apply] dry-run prima dell'applicazione"
fw1_sudo "ip netns exec $FW1_NETNS iptables-restore --test /tmp/fw1.redial-only.rules"

echo "[apply] applico FW1^"
fw1_sudo "ip netns exec $FW1_NETNS iptables-restore /tmp/fw1.redial-only.rules"

echo "[apply] OK"

echo
echo "=== FW1 FORWARD prime 30 regole ==="
fw1_sudo "ip netns exec $FW1_NETNS iptables -S FORWARD | head -30"

echo
echo "[INFO] FW2 non è stato toccato."
