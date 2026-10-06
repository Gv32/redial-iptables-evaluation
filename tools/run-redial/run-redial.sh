#!/usr/bin/env bash
# run-redial.sh — orchestratore REDIAL: listener (TAP+RX[+DST]) + sendpkts (SX)
# Derivato da run-experiment.sh (Caratterizzazione switch), adattato a sendpkts:
#   * il generatore e' sendpkts (pacchetti dai CSV net1/net2, split %, rampa totale)
#   * scrive l'epoch di start (--epoch-file) per allineare le catture
#   * filtro listener generico "udp" (le porte dst variano col ruleset)
set -euo pipefail

# default
OUTDIR="./captures"
NET1="packets_net1.csv"
NET2="packets_net2.csv"
SPLIT="50,50"
CPU=9                       # core ISOLATO per il sender (come udpramp)
RAMP=""
BPF="udp"
SENDPKTS="${SENDPKTS:-./sendpkts}"
LISTEN_SH="${LISTEN_SH:-./listen-redial.sh}"
GRACE_BEFORE=2             # attesa dopo l'avvio del listener
GRACE_AFTER="${GRACE_AFTER:-3}"  # margine extra di cattura dopo la fine del generatore

usage() {
  cat <<EOF
Usage: sudo $0 [options] --ramp DUR:R1,R2,...,RN
  --net1 FILE     CSV vettore net1                 (default $NET1)
  --net2 FILE     CSV vettore net2                 (default $NET2)
  --split P1,P2   ripartizione % net1/net2         (default $SPLIT)
  --cpu  N        core isolato per sendpkts        (default $CPU)
  --out  DIR      cartella pcap + epoch            (default $OUTDIR)
  --bpf  FILTER   filtro tcpdump del listener      (default "$BPF")
  --ramp DUR:R1,...   spec rampa, Ri = pps TOTALE/step  (OBBLIGATORIO)
Env:
  SENDPKTS, LISTEN_SH = percorso a binario/script
  CAP_DST=1 IF_DST=<iface>  = cattura anche il sink d2 (net2)
Esempio (50/50, rampa fino a 800k tot = 400k+400k):
  sudo $0 --split 50,50 --cpu 9 \\
          --ramp 20:1,10,100,1000,10000,100000,400000,800000
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --net1)   NET1="$2";   shift 2 ;;
    --net2)   NET2="$2";   shift 2 ;;
    --split)  SPLIT="$2";  shift 2 ;;
    --cpu)    CPU="$2";    shift 2 ;;
    --out)    OUTDIR="$2"; shift 2 ;;
    --bpf)    BPF="$2";    shift 2 ;;
    --ramp)   RAMP="$2";   shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[ERR] opzione sconosciuta: $1"; usage; exit 1 ;;
  esac
done

[[ -z "$RAMP" ]]      && { echo "[ERR] --ramp obbligatorio"; usage; exit 1; }
[[ -x "$SENDPKTS"  ]] || { echo "[ERR] $SENDPKTS non eseguibile"; exit 1; }
[[ -x "$LISTEN_SH" ]] || { echo "[ERR] $LISTEN_SH non eseguibile"; exit 1; }
[[ -f "$NET1" ]]     || { echo "[ERR] $NET1 mancante"; exit 1; }
[[ -f "$NET2" ]]     || { echo "[ERR] $NET2 mancante"; exit 1; }

# durata totale dalla rampa: DUR_STEP * N_RATES (+ margine)
DUR_STEP="${RAMP%%:*}"
N_RATES=$(awk -F, '{print NF}' <<<"${RAMP#*:}")
GEN_SEC=$((DUR_STEP * N_RATES))
LISTEN_SEC=$((GEN_SEC + GRACE_BEFORE + GRACE_AFTER))

mkdir -p "$OUTDIR"
STAMP=$(date +%Y%m%d_%H%M%S)
EPOCH_FILE="$OUTDIR/ramp_start_${STAMP}.epoch"

echo "========================================"
echo "  vettori          : $NET1 / $NET2"
echo "  split            : $SPLIT (% net1/net2, sul rate TOTALE)"
echo "  rampa            : $RAMP  (Ri = pps totale/step)"
echo "  durata generator : ${GEN_SEC}s"
echo "  durata listener  : ${LISTEN_SEC}s"
echo "  filtro listener  : $BPF"
echo "  cartella out     : $OUTDIR"
echo "  epoch file       : $EPOCH_FILE"
echo "  CPU pin (sender) : $CPU"
echo "========================================"

# 1) listener in background
echo "[1/2] avvio listener (${LISTEN_SEC}s) ..."
"$LISTEN_SH" "$LISTEN_SEC" "$BPF" "$OUTDIR" &
LISTEN_PID=$!

trap 'echo "[!] interrotto, killo listener"; kill -INT $LISTEN_PID 2>/dev/null || true; wait 2>/dev/null || true; exit 130' INT TERM

# attendi che tcpdump sia armato nei namespace
sleep "$GRACE_BEFORE"

# 2) generatore in foreground (namespace SX)
echo "[2/2] avvio sendpkts ..."
ip netns exec SX "$SENDPKTS" \
    --net1 "$NET1" --net2 "$NET2" \
    --split "$SPLIT" --cpu "$CPU" \
    --epoch-file "$EPOCH_FILE" \
    --ramp "$RAMP"
GEN_RC=$?

echo "[*] attendo il listener (PID=$LISTEN_PID) ..."
wait "$LISTEN_PID" || true

echo
echo "[done] generatore exit=$GEN_RC"
echo "[done] epoch di start: $(cat "$EPOCH_FILE" 2>/dev/null || echo 'N/D')"
echo "[done] pcap prodotti (questa run):"
ls -lht "$OUTDIR"/*.pcap 2>/dev/null | head -n 3
