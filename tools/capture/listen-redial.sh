#!/usr/bin/env bash
# listen-redial.sh — cattura HW-timestamp in parallelo sui namespace del banco REDIAL
# Derivato da listen.sh (Offset porte / Caratterizzazione switch).
#
# Differenze rispetto a listen.sh:
#   * Filtro BPF generico "udp" (sendpkts usa MOLTE porte dst diverse, prese dal
#     ruleset: un filtro "port 5000" perderebbe quasi tutto). Override col 2o arg.
#   * Cattura sempre su TAP + RX (path dn = net1). Cattura OPZIONALE anche su DST
#     (path d2 = net2) con CAP_DST=1.
#
# Uso:    ./listen-redial.sh [DURATION] [BPF] [OUTDIR]
# Tuning via env:
#   IF_TAP IF_RX IF_DST  (interfacce nei rispettivi namespace)
#   NS_TAP NS_RX NS_DST  (nomi dei namespace)
#   CAP_DST=1            (attiva la cattura sul sink d2)
#   CPU_TAP CPU_RX CPU_DST  (core dedicati a tcpdump)
#   TCPDUMP_BUF_KB NIC_RING_RX
set -euo pipefail

DURATION="${1:-30}"
BPF="${2:-udp}"
OUTDIR="${3:-./captures}"

# --- namespace + interfacce (CONFERMA i nomi sul TS-P5 prima della prima run) ---
NS_TAP="${NS_TAP:-TAP}";  IF_TAP="${IF_TAP:-ens8191f3}"   # dn, no IP, promisc
NS_RX="${NS_RX:-RX}";     IF_RX="${IF_RX:-ens8191f2}"      # dn, 10.0.1.3 (sink net1)
NS_DST="${NS_DST:-DST}";  IF_DST="${IF_DST:-}"             # d2, 10.0.2.2 (sink net2)
CAP_DST="${CAP_DST:-0}"

# core dedicati a tcpdump (diversi dal core 9 isolato usato da sendpkts)
CPU_TAP="${CPU_TAP:-4}"
CPU_RX="${CPU_RX:-6}"
CPU_DST="${CPU_DST:-8}"

TCPDUMP_BUF_KB="${TCPDUMP_BUF_KB:-524288}"   # 512 MB
NIC_RING_RX="${NIC_RING_RX:-4096}"           # I350 max

if [[ "$CAP_DST" == "1" && -z "$IF_DST" ]]; then
    echo "[ERR] CAP_DST=1 ma IF_DST non impostata (interfaccia del sink d2)"; exit 1
fi

mkdir -p "$OUTDIR"
STAMP=$(date +%Y%m%d_%H%M%S)
TAP_PCAP="$OUTDIR/tap_${STAMP}.pcap"
RX_PCAP="$OUTDIR/rx_${STAMP}.pcap"
DST_PCAP="$OUTDIR/dst_${STAMP}.pcap"

# --- preflight: ring RX al massimo + offload off (GRO/LRO/TSO/GSO falserebbero
# timestamp e conteggi aggregando i frame prima della cattura) ---
preflight() {
    local ns="$1" iface="$2"
    sudo ip netns exec "$ns" ethtool -G "$iface" rx "$NIC_RING_RX" 2>/dev/null || true
    sudo ip netns exec "$ns" ethtool -K "$iface" gro off lro off tso off gso off 2>/dev/null || true
}
preflight "$NS_TAP" "$IF_TAP"
preflight "$NS_RX"  "$IF_RX"
[[ "$CAP_DST" == "1" ]] && preflight "$NS_DST" "$IF_DST"

# --- snapshot contatori NIC (per misurare drop hw/driver in modo certo) ---
snap() {
    sudo ip netns exec "$1" ethtool -S "$2" 2>/dev/null | \
        awk '/rx_(missed_errors|fifo_errors|no_buff_count|no_dma_resources|over_errors|dropped|long_byte_count)/{
            gsub(":",""); print $1, $2
        }'
}
snap "$NS_TAP" "$IF_TAP" > /tmp/et_pre_tap.txt
snap "$NS_RX"  "$IF_RX"  > /tmp/et_pre_rx.txt
[[ "$CAP_DST" == "1" ]] && snap "$NS_DST" "$IF_DST" > /tmp/et_pre_dst.txt

echo "Cattura ${DURATION}s   filtro='${BPF}'"
echo "  TAP=$IF_TAP(ns $NS_TAP, CPU$CPU_TAP)  -> $TAP_PCAP"
echo "  RX =$IF_RX(ns $NS_RX, CPU$CPU_RX)  -> $RX_PCAP"
[[ "$CAP_DST" == "1" ]] && echo "  DST=$IF_DST(ns $NS_DST, CPU$CPU_DST)  -> $DST_PCAP"
echo "  buffer tcpdump=${TCPDUMP_BUF_KB} KB   ring RX=${NIC_RING_RX}"

# tcpdump come FIGLIO DIRETTO della shell (niente subshell $(): la subshell
# orfanizzava il processo e "wait" ritornava subito senza attendere il flush).
LAST_PID=""
start_tcpdump() {
    local ns="$1" iface="$2" cpu="$3" out="$4" log="$5"
    sudo ip netns exec "$ns" \
        chrt -f 50 taskset -c "$cpu" \
        tcpdump -i "$iface" -j adapter_unsynced \
            --time-stamp-precision=nano -nn \
            -B "$TCPDUMP_BUF_KB" \
            -w "$out" "$BPF" \
            2>"$log" &
    LAST_PID=$!
}

start_tcpdump "$NS_TAP" "$IF_TAP" "$CPU_TAP" "$TAP_PCAP" /tmp/tcpdump_tap.log; PID_TAP=$LAST_PID
start_tcpdump "$NS_RX"  "$IF_RX"  "$CPU_RX"  "$RX_PCAP"  /tmp/tcpdump_rx.log;  PID_RX=$LAST_PID
PID_DST=""
if [[ "$CAP_DST" == "1" ]]; then
    start_tcpdump "$NS_DST" "$IF_DST" "$CPU_DST" "$DST_PCAP" /tmp/tcpdump_dst.log; PID_DST=$LAST_PID
fi

trap 'sudo kill -INT $PID_TAP $PID_RX $PID_DST 2>/dev/null; wait 2>/dev/null; exit 130' INT

sleep "$DURATION"

# SIGINT a tcpdump = flush + stampa "X received / Y dropped by kernel"
sudo kill -INT $PID_TAP $PID_RX $PID_DST 2>/dev/null || true
wait $PID_TAP $PID_RX $PID_DST 2>/dev/null || true

snap "$NS_TAP" "$IF_TAP" > /tmp/et_post_tap.txt
snap "$NS_RX"  "$IF_RX"  > /tmp/et_post_rx.txt
[[ "$CAP_DST" == "1" ]] && snap "$NS_DST" "$IF_DST" > /tmp/et_post_dst.txt

delta() {
    awk 'NR==FNR { a[$1]=$2; next }
         { if ($1 in a) {
             d = $2 - a[$1];
             if (d != 0) printf "  %-26s %12d -> %12d  (delta %+d)\n", $1, a[$1], $2, d
           }}' \
        "$1" "$2"
}

echo
echo "--- tcpdump TAP (kernel) ---"; grep -E "received|dropped" /tmp/tcpdump_tap.log || true
echo "--- tcpdump RX  (kernel) ---"; grep -E "received|dropped" /tmp/tcpdump_rx.log  || true
if [[ "$CAP_DST" == "1" ]]; then
    echo "--- tcpdump DST (kernel) ---"; grep -E "received|dropped" /tmp/tcpdump_dst.log || true
fi

echo "--- NIC TAP delta (hw/driver) ---"; delta /tmp/et_pre_tap.txt /tmp/et_post_tap.txt | grep . || echo "  (nessun delta)"
echo "--- NIC RX  delta (hw/driver) ---"; delta /tmp/et_pre_rx.txt  /tmp/et_post_rx.txt  | grep . || echo "  (nessun delta)"
if [[ "$CAP_DST" == "1" ]]; then
    echo "--- NIC DST delta (hw/driver) ---"; delta /tmp/et_pre_dst.txt /tmp/et_post_dst.txt | grep . || echo "  (nessun delta)"
fi

echo
# Conteggio VELOCE: "received by filter" lo stampa tcpdump stesso (zero ri-parsing).
# (Niente piu' "tcpdump -r | wc -l": su catture da milioni di pkt decodificava e
# stampava OGNI pacchetto -> stallo di minuti. Era la causa del "listener impallato".)
cnt() { awk '/received by filter/{print $1; exit}' "$1" 2>/dev/null; }
sz()  { du -h "$1" 2>/dev/null | cut -f1; }
echo "Pacchetti catturati (received by filter) + dimensione file:"
echo "  TAP: $(cnt /tmp/tcpdump_tap.log) pkt   ($(sz "$TAP_PCAP"))"
echo "  RX:  $(cnt /tmp/tcpdump_rx.log) pkt   ($(sz "$RX_PCAP"))"
[[ "$CAP_DST" == "1" ]] && echo "  DST: $(cnt /tmp/tcpdump_dst.log) pkt   ($(sz "$DST_PCAP"))"
echo "[i] conteggio esatto on-demand (lento su file grandi): capinfos -c <file.pcap>"
