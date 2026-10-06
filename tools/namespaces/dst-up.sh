#!/bin/sh
# dst-up.sh — porta su il netns DST (sink del path d2) su TS-P5.
# Uso: sudo ./dst-up.sh up|down|status
# Idempotente.

set -eu

NS=DST
IF=ens8191f0          # 4ª porta I350 (caratterizzata in "Offset porte")
IP=10.0.2.2/30        # in ptp_dst (P2P verso FW2.out = 10.0.2.1)
GW=10.0.2.1           # FW2.out, default gateway per ARP/ICMP di ritorno

ns_exec() { ip netns exec "$NS" "$@"; }
need_root() { [ "$(id -u)" -eq 0 ] || { echo "Serve root (sudo)." >&2; exit 1; }; }

cmd_up() {
    need_root

    if ip netns list | grep -qw "$NS"; then
        echo "[=] netns $NS esiste già"
    else
        ip netns add "$NS"; echo "[+] netns $NS creato"
    fi

    if ip link show "$IF" >/dev/null 2>&1; then
        ip link set "$IF" down 2>/dev/null || true
        ip addr flush dev "$IF" 2>/dev/null || true
        ip link set "$IF" netns "$NS"
        echo "[+] $IF -> $NS"
    elif ns_exec ip link show "$IF" >/dev/null 2>&1; then
        echo "[=] $IF già in $NS"
    else
        echo "[!] interfaccia $IF non trovata" >&2; exit 1
    fi

    ns_exec ip addr flush dev "$IF"
    ns_exec ip addr add "$IP" dev "$IF"
    ns_exec ip link set lo  up
    ns_exec ip link set "$IF" up
    ns_exec ip link set "$IF" promisc on

    # sink: NO forwarding, rp_filter rilassato per accettare frame con dst != ip locale
    ns_exec sysctl -qw net.ipv4.ip_forward=0
    ns_exec sysctl -qw "net.ipv4.conf.$IF.rp_filter=0"
    ns_exec sysctl -qw "net.ipv4.conf.$IF.accept_local=1"

    # default route per generare ARP/ICMP di risposta durante smoke test
    ns_exec ip route replace default via "$GW" dev "$IF" onlink

    # silenzia i pacchetti che non sono diretti al transit (evita log INPUT)
    ns_exec iptables -F
    ns_exec iptables -A INPUT -i "$IF" ! -d 10.0.2.2 -j DROP
    ns_exec iptables -P FORWARD DROP
    ns_exec iptables -P OUTPUT ACCEPT
    ns_exec iptables -P INPUT  ACCEPT

    echo "[OK] netns $NS pronto"
    cmd_status
}

cmd_down() {
    need_root
    if ip netns list | grep -qw "$NS"; then
        if ns_exec ip link show "$IF" >/dev/null 2>&1; then
            ns_exec ip link set "$IF" promisc off 2>/dev/null || true
            ns_exec ip link set "$IF" down 2>/dev/null || true
            ns_exec ip link set "$IF" netns 1
            echo "[-] $IF -> root ns"
        fi
        ip netns del "$NS"
        echo "[-] netns $NS rimosso"
    else
        echo "[=] netns $NS non esiste"
    fi
}

cmd_status() {
    if ! ip netns list | grep -qw "$NS"; then
        echo "[=] $NS non esiste"; return 0
    fi
    echo "----- ip -br addr -----"; ns_exec ip -br addr
    echo "----- ip -d link show $IF -----"; ns_exec ip -d link show "$IF" | head -3
    echo "----- ip route -----";    ns_exec ip route
    echo "----- forwarding -----";  ns_exec sysctl -n net.ipv4.ip_forward
    echo "----- iptables INPUT -----"; ns_exec iptables -nvL INPUT
}

case "${1:-up}" in
    up)     cmd_up ;;
    down)   cmd_down ;;
    status) cmd_status ;;
    *)      echo "Uso: $0 {up|down|status}" >&2; exit 1 ;;
esac
