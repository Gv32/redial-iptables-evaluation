#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
source ./inventory.sh

[ -f "$WORKDIR/fw1.xml" ] || {
  echo "[ERR] manca $WORKDIR/fw1.xml"
  echo "      Esegui prima: ./collect-fw1.sh"
  exit 1
}

echo "[generate] genero FW1^ REDIAL-only"
echo "[generate] d2=$D2_CIDR"
echo "[generate] dn=$DN_CIDR"

./redial_fw1_only.py \
  --fw1-xml "$WORKDIR/fw1.xml" \
  --d2 "$D2_CIDR" \
  --dn "$DN_CIDR" \
  --out-fw1 "$WORKDIR/fw1.redial-only.rules"

echo "[generate] scritto: $WORKDIR/fw1.redial-only.rules"

echo
echo "=== shortcut attesa ==="
grep -- "-d $D2_CIDR -j ACCEPT" "$WORKDIR/fw1.redial-only.rules" || {
  echo "[WARN] shortcut non trovata con grep esatto"
}

echo
echo "=== conteggio regole FORWARD ==="
echo -n "originale: "
grep -c "^-A FORWARD" "$WORKDIR/fw1.backup.rules" || true

echo -n "fw1-only:  "
grep -c "^-A FORWARD" "$WORKDIR/fw1.redial-only.rules" || true

echo
echo "=== prime 80 righe ruleset generato ==="
sed -n '1,80p' "$WORKDIR/fw1.redial-only.rules"
