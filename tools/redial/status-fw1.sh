#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "[status] carico lib.sh"
source ./lib.sh

echo "[status] WORKDIR=$WORKDIR"
echo "[status] FW1=$SSH_USER@$FW1_MGMT"
echo "[status] FW1_NETNS=$FW1_NETNS"
echo "[status] D2=$D2_CIDR"
echo "[status] PASS_FILE=$PASS_FILE"

[ -f "$PASS_FILE" ] || die "PASS_FILE non trovato: $PASS_FILE"

echo
echo "[status] test SSH semplice"
fw1 "hostname; ip netns list"

echo
echo "[status] test sudo semplice"
fw1_sudo "true"

echo
echo "[status] FW1 FORWARD prime 50 regole"
fw1_sudo "ip netns exec $FW1_NETNS iptables -S FORWARD | head -50"

echo
echo "[status] cerca shortcut verso $D2_CIDR"
fw1_sudo "ip netns exec $FW1_NETNS iptables -S FORWARD | grep -- '-d $D2_CIDR -j ACCEPT' || true"

echo
echo "[status] OK"
