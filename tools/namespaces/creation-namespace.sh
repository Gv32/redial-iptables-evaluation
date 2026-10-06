#!/usr/bin/env bash
# creation-namespace.sh — ricrea SX / TAP / RX (+ DST, non usato nel single-FW)
# Uso: sudo ./creation-namespace.sh {up|status|down}
set -euo pipefail

IF_SX="enp1s0f1"      # generatore, d0
IF_TAP="ens8191f3"    # cattura, no IP
IF_RX="ens8191f2"     # sink net1/dn
IF_DST="ens8191f0"    # sink d2 (solo banco a 2 FW, innocuo crearlo)

up() {
    for ns in SX TAP RX DST; do
        ip netns add "$ns" 2>/dev/null || true
        ip netns exec "$ns" ip link set lo up
    done

    # sposta le interfacce (solo se ancora nel root ns)
    ip link show "$IF_SX"  >/dev/null 2>&1 && ip link set "$IF_SX"  netns SX
    ip link show "$IF_TAP" >/dev/null 2>&1 && ip link set "$IF_TAP" netns TAP
    ip link show "$IF_RX"  >/dev/null 2>&1 && ip link set "$IF_RX"  netns RX
    ip link show "$IF_DST" >/dev/null 2>&1 && ip link set "$IF_DST" netns DST

    # SX: 10.0.0.1/24, gw = FW1
    ip netns exec SX ip addr flush dev "$IF_SX"
    ip netns exec SX ip addr add 10.0.0.1/24 dev "$IF_SX"
    ip netns exec SX ip link set "$IF_SX" up
    ip netns exec SX ip route replace default via 10.0.0.3

    # TAP: nessun IP, promisc
    ip netns exec TAP ip link set "$IF_TAP" up promisc on

    # RX: 10.0.1.3/24, promisc, gw = FW1.out
    ip netns exec RX ip addr flush dev "$IF_RX"
    ip netns exec RX ip addr add 10.0.1.3/24 dev "$IF_RX"
    ip netns exec RX ip link set "$IF_RX" up promisc on
    ip netns exec RX ip route replace default via 10.0.1.1

    # DST: 10.0.2.2/30, promisc (non usato nel single-FW)
    ip netns exec DST ip addr flush dev "$IF_DST"
    ip netns exec DST ip addr add 10.0.2.2/30 dev "$IF_DST"
    ip netns exec DST ip link set "$IF_DST" up promisc on
    ip netns exec DST ip route replace default via 10.0.2.1 onlink

    # leaf: niente forwarding
    for ns in SX TAP RX DST; do
        ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=0
    done
    echo "[OK] namespace pronti"; status
}

status() {
    for ns in SX TAP RX DST; do
        echo "----- $ns -----"
        ip netns exec "$ns" ip -br addr 2>/dev/null || echo "  (non esiste)"
        ip netns exec "$ns" ip route 2>/dev/null || true
    done
}

down() {
    ip netns exec TAP ip link set "$IF_TAP" netns 1 2>/dev/null || true
    ip netns exec RX  ip link set "$IF_RX"  netns 1 2>/dev/null || true
    ip netns exec SX  ip link set "$IF_SX"  netns 1 2>/dev/null || true
    ip netns exec DST ip link set "$IF_DST" netns 1 2>/dev/null || true
    for ns in SX TAP RX DST; do ip netns del "$ns" 2>/dev/null || true; done
    echo "[OK] namespace rimossi"
}

case "${1:-up}" in
    up) up ;; status) status ;; down) down ;;
    *) echo "Uso: $0 {up|status|down}" >&2; exit 1 ;;
esac
