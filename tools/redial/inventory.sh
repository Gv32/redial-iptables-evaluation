#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# REDIAL single FW — FW1-only inventory
###############################################################################

# Dominî logici
export D0_CIDR="${D0_CIDR:-10.0.0.0/24}"
export DN_CIDR="${DN_CIDR:-10.0.1.0/24}"
export D2_CIDR="${D2_CIDR:-10.0.2.0/24}"

# Nodo FW1
export FW1_MGMT="${FW1_MGMT:-192.168.100.103}"
export FW1_NETNS="${FW1_NETNS:-FW}"
export SSH_USER="${SSH_USER:-drago}"

# Password già presente nel progetto REDIAL normale
export PASS_FILE="${PASS_FILE:-$HOME/redial/.fwpass}"

# Cartella run
if [ -z "${WORKDIR:-}" ]; then
  export WORKDIR="$PWD/runs/$(date +%Y%m%d-%H%M%S)"
fi

mkdir -p "$WORKDIR"

echo "[inventory] WORKDIR=$WORKDIR"
echo "[inventory] FW1=$SSH_USER@$FW1_MGMT netns=$FW1_NETNS"
echo "[inventory] d0=$D0_CIDR dn=$DN_CIDR d2=$D2_CIDR"
