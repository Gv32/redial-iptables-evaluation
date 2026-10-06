#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
source ./lib.sh

BACKUP="$WORKDIR/fw1.backup.rules"

[ -f "$BACKUP" ] || die "manca $BACKUP; devi usare la WORKDIR corretta"

echo "[rollback] ripristino ruleset originale FW1"
fw1_put "$BACKUP" /tmp/fw1.backup.rules

fw1_sudo "ip netns exec $FW1_NETNS iptables-restore /tmp/fw1.backup.rules"

echo "[rollback] OK"

echo
echo "=== FW1 FORWARD prime 30 regole ==="
fw1_sudo "ip netns exec $FW1_NETNS iptables -S FORWARD | head -30"
