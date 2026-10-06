#!/usr/bin/env bash
# load-fw.sh — carica un ruleset sulla chain FORWARD del netns FW da TS-P5.
# Uso: ./load-fw.sh <file.rules> [regole_attese]   (default 601)
set -euo pipefail

FW="drago@192.168.100.103"
RULES="${1:?uso: ./load-fw.sh <file.rules> [regole attese]}"
EXP="${2:-601}"

[ -f "$RULES" ] || { echo "[ERR] file non trovato: $RULES"; exit 1; }

scp -q "$RULES" "$FW:/tmp/fw_load.rules"

# dry-run prima di applicare: se il file è rotto il FW resta com'era
ssh "$FW" 'sudo ip netns exec FW iptables-restore --test /tmp/fw_load.rules'
ssh "$FW" 'sudo ip netns exec FW iptables-restore < /tmp/fw_load.rules'

N=$(ssh "$FW" 'sudo ip netns exec FW iptables -S FORWARD | grep -c "^-A"')
[ "$N" = "$EXP" ] || { echo "[ERR] $N regole sul FW (attese $EXP)"; exit 1; }

H=$(ssh "$FW" 'sudo ip netns exec FW iptables -S FORWARD' | grep -v '^-P' \
    | grep -n 'REDIAL:net2' | head -1 | cut -d: -f1 || true)
P=$(ssh "$FW" 'sudo ip netns exec FW iptables -S FORWARD | head -1')

echo "[OK] $RULES caricato: $N regole, policy '$P', prima regola net2 in posizione ${H:-n/d}"
