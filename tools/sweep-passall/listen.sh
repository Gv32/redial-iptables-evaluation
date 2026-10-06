#!/usr/bin/env bash
# listen.sh — cattura HW-timestamp in parallelo su TAP e RX
# Uso:    ./listen.sh [DURATION] [PORT] [OUTDIR]
# Tuning via env: CPU_TAP CPU_RX TCPDUMP_BUF_KB NIC_RING_RX
set -euo pipefail

DURATION="${1:-30}"
PORT="${2:-5000}"
OUTDIR="${3:-./captures}"

IF_TAP="ens8191f3"
IF_RX="ens8191f2"

# core dedicati a tcpdump (diversi dal core 2 usato da udpramp)
CPU_TAP="${CPU_TAP:-4}"
CPU_RX="${CPU_RX:-6}"

# buffer kernel di tcpdump in KB (default tcpdump = 2 MB; qui 512 MB)
TCPDUMP_BUF_KB="${TCPDUMP_BUF_KB:-524288}"

# dimensione ring RX della NIC (I350 max = 4096)
NIC_RING_RX="${NIC_RING_RX:-4096}"

mkdir -p "$OUTDIR"
STAMP=$(date +%Y%m%d_%H%M%S)
TAP_PCAP="$OUTDIR/tap_${STAMP}.pcap"
RX_PCAP="$OUTDIR/rx_${STAMP}.pcap"

# --- preflight: ring RX al massimo + offload off (GRO/LRO/TSO/GSO
# aggregherebbero frame prima della cattura, falsando timestamp e conteggi)
preflight() {
    local ns="$1" iface="$2"
    sudo ip netns exec "$ns" ethtool -G "$iface" rx "$NIC_RING_RX" 2>/dev/null || true
    sudo ip netns exec "$ns" ethtool -K "$iface" gro off lro off tso off gso off 2>/dev/null || true
}
preflight TAP "$IF_TAP"
preflight RX  "$IF_RX"

# --- snapshot contatori NIC (per misurare drop hw/driver in modo certo) ---
snap() {
    sudo ip netns exec "$1" ethtool -S "$2" 2>/dev/null | \
        awk '/rx_(missed_errors|fifo_errors|no_buff_count|no_dma_resources|over_errors|dropped|long_byte_count)/{
            gsub(":",""); print $1, $2
        }'
}
snap TAP "$IF_TAP" > /tmp/et_pre_tap.txt
snap RX  "$IF_RX"  > /tmp/et_pre_rx.txt

echo "Cattura ${DURATION}s   TAP=$IF_TAP(CPU$CPU_TAP)   RX=$IF_RX(CPU$CPU_RX)   porta=$PORT"
echo "  buffer tcpdump=${TCPDUMP_BUF_KB} KB   ring RX=${NIC_RING_RX}"
echo "  -> $TAP_PCAP"
echo "  -> $RX_PCAP"

# --- lancia tcpdump con priorita' RT su core dedicato e socket buffer maggiorato ---
sudo ip netns exec TAP \
    chrt -f 50 taskset -c "$CPU_TAP" \
    tcpdump -i "$IF_TAP" -j adapter_unsynced \
        --time-stamp-precision=nano -nn \
        -B "$TCPDUMP_BUF_KB" \
        -w "$TAP_PCAP" "udp and port $PORT" \
        2>/tmp/tcpdump_tap.log &
PID_TAP=$!

sudo ip netns exec RX \
    chrt -f 50 taskset -c "$CPU_RX" \
    tcpdump -i "$IF_RX" -j adapter_unsynced \
        --time-stamp-precision=nano -nn \
        -B "$TCPDUMP_BUF_KB" \
        -w "$RX_PCAP" "udp and port $PORT" \
        2>/tmp/tcpdump_rx.log &
PID_RX=$!

trap 'sudo kill -INT $PID_TAP $PID_RX 2>/dev/null; wait 2>/dev/null; exit 130' INT

sleep "$DURATION"

# SIGINT a tcpdump = flush + stampa "X received / Y dropped by kernel"
sudo kill -INT $PID_TAP $PID_RX 2>/dev/null || true
wait $PID_TAP $PID_RX 2>/dev/null || true

snap TAP "$IF_TAP" > /tmp/et_post_tap.txt
snap RX  "$IF_RX"  > /tmp/et_post_rx.txt

delta() {
    awk 'NR==FNR { a[$1]=$2; next }
         { if ($1 in a) {
             d = $2 - a[$1];
             if (d != 0) printf "  %-26s %12d -> %12d  (delta %+d)\n", $1, a[$1], $2, d
           }}' \
        "$1" "$2"
}

echo
echo "--- tcpdump TAP (kernel) ---"
grep -E "received|dropped" /tmp/tcpdump_tap.log || true
echo "--- tcpdump RX  (kernel) ---"
grep -E "received|dropped" /tmp/tcpdump_rx.log  || true

echo "--- NIC TAP delta (hw/driver) ---"
delta /tmp/et_pre_tap.txt /tmp/et_post_tap.txt | grep . || echo "  (nessun delta)"
echo "--- NIC RX  delta (hw/driver) ---"
delta /tmp/et_pre_rx.txt  /tmp/et_post_rx.txt  | grep . || echo "  (nessun delta)"

echo
echo "Pacchetti catturati:"
echo "  TAP: $(sudo tcpdump -r "$TAP_PCAP" 2>/dev/null | wc -l)"
echo "  RX:  $(sudo tcpdump -r "$RX_PCAP"  2>/dev/null | wc -l)"
