#!/usr/bin/env bash
# collect.sh — scarica iptables-save dalle netns (FW/FW2) e converte a XML
# localmente sul bastion (per evitare conflitti di stdin con sudo -S).
set -u
source "$(dirname "$0")/inventory.sh"

_sudo() {
  local host="$1"; shift
  cat "$PASS_FILE" | sshpass -f "$PASS_FILE" ssh -o StrictHostKeyChecking=accept-new \
    "$SSH_USER@$host" "sudo -S -p '' $*"
}

# ── FW1 ──────────────────────────────────────────────────────────────────────
echo "[collect] FW1 ($FW1_IP, netns=$FW1_NETNS) ..."
_sudo "$FW1_IP" "ip netns exec $FW1_NETNS iptables-save" > "$WORKDIR/fw1.backup.rules"
if [ ! -s "$WORKDIR/fw1.backup.rules" ]; then
  echo "[collect][WARN] FW1 netns vuota — uso un filter vuoto come stub"
  cat > "$WORKDIR/fw1.backup.rules" <<'RUL'
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
RUL
fi
iptables-xml < "$WORKDIR/fw1.backup.rules" > "$WORKDIR/fw1.xml"

# ── FW2 ──────────────────────────────────────────────────────────────────────
echo "[collect] FW2 ($FW2_IP, netns=$FW2_NETNS) ..."
_sudo "$FW2_IP" "ip netns exec $FW2_NETNS iptables-save" > "$WORKDIR/fw2.backup.rules"
if [ ! -s "$WORKDIR/fw2.backup.rules" ]; then
  echo "[collect][WARN] FW2 netns vuota — uso un filter vuoto come stub"
  cat > "$WORKDIR/fw2.backup.rules" <<'RUL'
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
RUL
fi
iptables-xml < "$WORKDIR/fw2.backup.rules" > "$WORKDIR/fw2.xml"

echo "[collect] OK — files in $WORKDIR"
ls -la "$WORKDIR"
