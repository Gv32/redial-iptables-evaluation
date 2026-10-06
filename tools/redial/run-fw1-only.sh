#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

###############################################################################
# run-fw1-only.sh
#
# Comando unico per:
#   1. leggere il ruleset corrente di FW1
#   2. convertirlo in XML
#   3. generare FW1^ post-REDIAL-only
#   4. validare con iptables-restore --test
#   5. applicare FW1^ su FW1
#
# ATTENZIONE:
#   va lanciato quando FW1 è in configurazione PRE/originale.
#   Se FW1 è già post-REDIAL-only, prima fare rollback.
###############################################################################

# Crea nuova WORKDIR se non già impostata
if [ -z "${WORKDIR:-}" ]; then
  export WORKDIR="$PWD/runs/$(date +%Y%m%d-%H%M%S)"
fi

source ./inventory.sh

echo
echo "======================================================================"
echo "[run] REDIAL FW1-only"
echo "======================================================================"
echo "[run] WORKDIR=$WORKDIR"
echo "[run] FW1=$SSH_USER@$FW1_MGMT netns=$FW1_NETNS"
echo "[run] d0=$D0_CIDR"
echo "[run] dn=$DN_CIDR"
echo "[run] d2=$D2_CIDR"
echo "======================================================================"
echo

echo "[run] Step 1/4: collect FW1 originale"
./collect-fw1.sh

echo
echo "[run] Step 2/4: genera FW1^ post-REDIAL-only"
./generate-fw1-only.sh

echo
echo "[run] Step 3/4: valida ruleset con iptables-restore --test"
./validate-fw1-only.sh

echo
echo "[run] Step 4/4: applica FW1^ su FW1"
./apply-fw1-only.sh

echo
echo "======================================================================"
echo "[run] COMPLETATO"
echo "======================================================================"
echo "[run] FW1 è ora in configurazione POST REDIAL FW1-only"
echo "[run] Backup PRE salvato in:"
echo "      $WORKDIR/fw1.backup.rules"
echo "[run] Ruleset generato salvato in:"
echo "      $WORKDIR/fw1.redial-only.rules"
echo
echo "[run] Per tornare al PRE:"
echo "      export WORKDIR=$WORKDIR"
echo "      ./start.sh pre"
echo "======================================================================"
