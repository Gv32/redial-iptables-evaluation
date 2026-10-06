#!/usr/bin/env python3
"""gen_fw_rules_v6.py - Generatore ruleset FW1 per il banco REDIAL.

Variante di v5 che corregge --order mixed con split asimmetrici
(--net-split / --net-ratio): l'interleaving e' PROPORZIONALE al rapporto
|net1|:|net2| invece dell'alternanza rigida 1:1.

  * v5: con 138/412 emetteva n1 n2 n1 n2 ... finche' net1 si esauriva, poi
    scaricava tutte le net2 residue in un blocco puro in coda (semi-n1n2).
  * v6: fusione tipo Bresenham, deterministica e SENZA RNG. La prima regola
    e' SEMPRE net1 (se disponibile), poi il Bresenham prosegue proporzionale:
    con 138/412 il pattern e' n1 n2 n2 n2 n1 n2 n2 n2 ...; con liste di pari
    lunghezza degenera nell'alternanza classica n1 n2 n1 n2 -> output
    bit-per-bit identico a v5 su split simmetrici e mirror. --order random e
    --wildcard-pos mixed restano invariati (stesso consumo di RNG).
  * nuovo flag --no-final-log: omette la riga finale di LOG default-drop
    (FW-DROP-DEF). Senza flag comportamento e conteggi invariati; con il
    flag il totale scende di 1 e --net-ratio ricalcola da solo il budget
    ACCEPT (niente +1 final).
  * header e riepilogo riportano il net-split EFFETTIVO anche con
    --net-ratio (la v5 stampava 'mirror').

Tutto il resto (--wildcard-action, --net-ratio, mirror, anti-shadow, ordini,
posizioni wildcard, final default-drop log) e' identico a v5.

Modello del banco REDIAL (invariato):
  * Sorgente unica: tutto il traffico entra da SX nella subnet 10.0.0.0/24,
    quindi OGNI regola ACCEPT ha  -s 10.0.0.0/24.
  * Doppia destinazione speculare (mirror 1:1):
      - net1 = 10.0.1.0/24  (dn, filtrata solo da FW1, misurata a RX)
      - net2 = 10.0.2.0/24  (subnet di offload: presente in FW1 e poi
        spostata da REDIAL su FW2)
    Le regole sono ~50% net1 e ~50% net2.
  * Solo UDP.
  * Nessuna shadowed rule: le porte del catalogo sono UNICHE, quindi due
    ACCEPT non possono mai condividere (proto,dport) e all'interno dello
    stesso servizio le destinazioni sono disgiunte. I wildcard larghi /22
    (che coprono ENTRAMBE le net) hanno porte disgiunte dagli ACCEPT, quindi
    possono stare in coda, in testa o mescolati (--wildcard-pos) senza
    creare shadowing, sia in deny che in accept.
  * Gli indirizzi .1 (FW1.out), .2 (FW2.in) e .3 (RX-sink) NON sono mai usati
    come destinazione.
"""
import argparse
import ipaddress
import random
import sys
from datetime import datetime

SRC = "10.0.0.0/24"
NET1 = "10.0.1.0/24"
NET1_PREFIX = "10.0.1."
NET2_PREFIX = "10.0.2."
# net, FW1.out(.1), FW2.in(.2), RX-sink(.3), broadcast(.255)
RESERVED_OCTETS = {0, 1, 2, 3, 255}

# Catalogo servizi UDP realistici. La porta e' UNICA per ogni servizio:
# cosi' due regole non condividono mai (proto,dport) e lo shadowing fra ACCEPT
# e' strutturalmente impossibile.
#   (name, dport, descr, mode, zone)
#   mode: "hosts" -> F host /32 distinti ; "wide" -> tutta 10.0.1.0/24 ;
#         "block" -> sub-blocchi disgiunti (vedi BLOCKS)
SERVICES = [
    # --- ICS / OT (SCADA, PLC, RTU) ---
    ("modbus",      502,   "modbus-udp",          "hosts", "ics"),
    ("dnp3",        20000, "dnp3-udp",            "hosts", "ics"),
    ("iec104",      2404,  "iec60870-5-104-udp",  "hosts", "ics"),
    ("enip_io",     2222,  "ethernetip-io",       "hosts", "ics"),
    ("enip_exp",    44818, "ethernetip-explicit", "hosts", "ics"),
    ("profinet_rt", 34962, "profinet-rt",         "hosts", "ics"),
    ("profinet_al", 34964, "profinet-alarm",      "hosts", "ics"),
    ("opcua",       4840,  "opcua-udp",           "block", "ics"),
    ("fins",        9600,  "omron-fins-udp",      "hosts", "ics"),
    ("melsec",      5007,  "mitsubishi-melsec",   "hosts", "ics"),
    ("ethercat",    34980, "ethercat-udp",        "hosts", "ics"),
    ("bacnet",      47809, "bacnet-ot",           "hosts", "ics"),
    ("coap",        5683,  "coap-udp",            "hosts", "ics"),
    ("coaps",       5684,  "coaps-dtls",          "hosts", "ics"),
    # --- IT infrastructure ---
    ("dns",         53,    "dns-udp",             "wide",  "srv"),
    ("ntp",         123,   "ntp",                 "wide",  "srv"),
    ("snmp_get",    161,   "snmp-get",            "wide",  "srv"),
    ("snmp_trap",   162,   "snmp-trap",           "hosts", "srv"),
    ("syslog",      514,   "syslog",              "wide",  "srv"),
    ("radius_auth", 1812,  "radius-auth",         "hosts", "srv"),
    ("radius_acct", 1813,  "radius-acct",         "hosts", "srv"),
    ("tacacs",      49,    "tacacs-udp",          "hosts", "srv"),
    ("kerberos",    88,    "kerberos-udp",        "hosts", "srv"),
    ("cldap",       389,   "cldap-udp",           "hosts", "srv"),
    ("http3",       80,    "http3-cleartext",     "hosts", "srv"),
    ("https_quic",  443,   "https-quic",          "hosts", "srv"),
    ("https_alt",   8443,  "https-quic-alt",      "hosts", "srv"),
    ("ipsec_ike",   500,   "ipsec-ike",           "hosts", "srv"),
    ("ipsec_natt",  4500,  "ipsec-nat-t",         "hosts", "srv"),
    ("openvpn",     1194,  "openvpn",             "hosts", "srv"),
    ("sip",         5060,  "sip-udp",             "hosts", "srv"),
    ("netflow",     2055,  "netflow-v9",          "hosts", "srv"),
    ("sflow",       6343,  "sflow-v5",            "hosts", "srv"),
    # --- Monitoring / management ---
    ("zbx_agent",   10050, "zabbix-agent-udp",    "hosts", "mon"),
    ("zbx_srv",     10051, "zabbix-server-udp",   "hosts", "mon"),
    ("prometheus",  9090,  "prom-quic",           "hosts", "mon"),
    ("node_exp",    9100,  "node-exporter-udp",   "hosts", "mon"),
    ("influx",      8089,  "influx-line-udp",     "hosts", "mon"),
    ("grafana",     3000,  "grafana-quic",        "hosts", "mon"),
    ("fluentd",     24224, "fluentd-udp",         "hosts", "mon"),
    # --- Backup / storage ---
    ("nfs",         2049,  "nfs-udp",             "hosts", "stor"),
    ("veeam",       6160,  "veeam-udp",           "hosts", "stor"),
    ("bacula_dir",  9101,  "bacula-dir-udp",      "hosts", "stor"),
    ("bacula_sd",   9103,  "bacula-sd-udp",       "hosts", "stor"),
    ("isns",        3205,  "isns-udp",            "hosts", "stor"),
]

# Destinazioni a sub-blocco disgiunto per i servizi in mode "block".
BLOCKS = {
    "opcua": ["10.0.1.16/28", "10.0.1.32/28"],
}

# Porte note-insicure: vengono loggate e (in base a --wildcard-action) DROPpate
# o ACCETTate con un wildcard /22 che copre ENTRAMBE le net. Sono porte DIVERSE
# da quelle del catalogo ACCEPT, quindi non oscurano nulla.
INSECURE_WILDCARD = [
    ("udp", "19",    "chargen-amp"),
    ("udp", "67",    "dhcp-server-rogue"),
    ("udp", "68",    "dhcp-client-rogue"),
    ("udp", "69",    "tftp"),
    ("udp", "111",   "rpcbind-udp"),
    ("udp", "137",   "netbios-ns"),
    ("udp", "138",   "netbios-dgm"),
    ("udp", "177",   "xdmcp"),
    ("udp", "520",   "rip-cleartext"),
    ("udp", "623",   "ipmi-rmcp"),
    ("udp", "1645",  "radius-legacy-auth"),
    ("udp", "1646",  "radius-legacy-acct"),
    ("udp", "1701",  "l2tp-uncontrolled"),
    ("udp", "1883",  "mqtt-cleartext"),
    ("udp", "1900",  "ssdp"),
    ("udp", "4789",  "vxlan-cross-segment"),
    ("udp", "5353",  "mdns"),
    ("udp", "5355",  "llmnr"),
    ("udp", "6000",  "x11-udp"),
    ("udp", "11211", "memcached-udp"),
    ("udp", "17185", "vxworks-debug"),
    ("udp", "27015", "steam-srcds"),
    ("udp", "30718", "lantronix-discovery"),
    ("udp", "47808", "bacnet-scan"),
]

# Porte wildcard AGGIUNTIVE (per --wildcard-rules alti, es. 50 regole).
# Sempre UDP, sempre disgiunte dal catalogo ACCEPT e da INSECURE_WILDCARD.
EXTRA_WILDCARD = [
    ("udp", "7",     "echo-amp"),
    ("udp", "9",     "discard"),
    ("udp", "13",    "daytime-amp"),
    ("udp", "17",    "qotd-amp"),
    ("udp", "37",    "time-amp"),
    ("udp", "42",    "wins"),
    ("udp", "113",   "auth-udp"),
    ("udp", "135",   "msrpc-udp"),
    ("udp", "427",   "slp-amp"),
    ("udp", "464",   "kpasswd"),
    ("udp", "517",   "talk"),
    ("udp", "518",   "ntalk"),
    ("udp", "593",   "http-rpc-epmap"),
    ("udp", "749",   "kerberos-adm"),
    ("udp", "1434",  "mssql-monitor-slammer"),
    ("udp", "1604",  "citrix-ica"),
    ("udp", "2302",  "gamesrv-probe"),
    ("udp", "3283",  "apple-remote-desktop"),
    ("udp", "3389",  "rdp-udp"),
    ("udp", "3702",  "ws-discovery-amp"),
    ("udp", "5093",  "sentinel-lm"),
    ("udp", "5351",  "nat-pmp"),
    ("udp", "10001", "ubiquiti-discovery"),
    ("udp", "10080", "amanda"),
    ("udp", "37810", "dahua-discovery"),
    ("udp", "49152", "ephemeral-probe"),
]


def mirror(dst):
    """net1 -> net2 (10.0.1.x -> 10.0.2.x)."""
    return dst.replace(NET1_PREFIX, NET2_PREFIX, 1)


def to_net(cidr):
    return ipaddress.ip_network(cidr, strict=False)


def covers(broader, narrower):
    return to_net(narrower).subnet_of(to_net(broader))


def host_pool():
    return [o for o in range(4, 255) if o not in RESERVED_OCTETS]


def build_net1(limit, seed, variants, n_wild=None, n1_target=None):
    """Costruisce la lista (ordinata per servizio) di destinazioni net1.

    Ritorna lista di dict: {name, port, descr, mode, zone, dst}.
    """
    pool = host_pool()
    wide = [s for s in SERVICES if s[3] == "wide"]
    block = [s for s in SERVICES if s[3] == "block"]
    hosts = [s for s in SERVICES if s[3] == "hosts"]

    if n_wild is None:
        n_wild = 2 * len(INSECURE_WILDCARD)
    if n1_target is None:
        n1_target = max(1, (limit - n_wild - 1) // 2)
    fixed = len(wide) + sum(len(BLOCKS[s[0]]) for s in block)
    remaining = max(0, n1_target - fixed)

    if variants is not None:
        F = max(1, variants)
    else:
        # ceil: garantisce di RAGGIUNGERE il target (round poteva restare sotto)
        F = max(1, -(-remaining // max(1, len(hosts))))
    F = min(F, len(pool))  # niente duplicati host per uno stesso servizio

    entries = []
    for idx, (name, port, descr, mode, zone) in enumerate(SERVICES):
        if mode == "wide":
            dsts = [NET1]
        elif mode == "block":
            dsts = list(BLOCKS[name])
        else:  # hosts
            offset = (seed * 131 + idx * 37) % len(pool)
            octets = [pool[(offset + k) % len(pool)] for k in range(F)]
            dsts = [f"{NET1_PREFIX}{o}/32" for o in octets]
        for dst in dsts:
            entries.append({"name": name, "port": str(port), "descr": descr,
                             "mode": mode, "zone": zone, "dst": dst})

    # Taglio al target net1 (approssimativamente 50% del budget).
    if len(entries) > n1_target:
        entries = entries[:n1_target]
    return entries, F


def assert_no_shadow(rules):
    """Verifica che nessun ACCEPT sia oscurato da un ACCEPT precedente con
    stesso (proto,dport) e destinazione piu' ampia. Ritorna lista di conflitti."""
    seen = {}
    conflicts = []
    for (src, dst, proto, port) in rules:
        prev = seen.setdefault((proto, port), [])
        for (s_old, d_old) in prev:
            if covers(d_old, dst):
                conflicts.append(((s_old, d_old), (src, dst), proto, port))
        prev.append((src, dst))
    return conflicts


def emit_line(src, dst, proto, port, target="ACCEPT", extra=""):
    base = f"-A FORWARD -s {src} -d {dst} -p {proto} -m {proto} --dport {port}"
    if extra:
        base += f" {extra}"
    return f"{base} -j {target}"


def main():
    ap = argparse.ArgumentParser(description="Generatore ruleset FW1 v6 (REDIAL)")
    ap.add_argument("-o", "--output", default="-")
    ap.add_argument("--limit", type=int, default=1000,
                    help="numero totale di regole desiderato (~50/50 net1/net2)")
    ap.add_argument("--seed", type=int, default=42,
                    help="seme per la scelta degli host destinazione")
    ap.add_argument("--variants", type=int, default=None,
                    help="forza il numero di host /32 per servizio (default: auto)")
    ap.add_argument("--order",
                    choices=["grouped", "mixed", "n1n2", "n2n1", "random"],
                    default="grouped",
                    help="ordine degli ACCEPT: grouped (per servizio net1->net2), "
                         "mixed (net1/net2 interleaved in modo PROPORZIONALE al "
                         "rapporto |net1|:|net2|; con liste uguali = alternanza "
                         "classica), n1n2 (tutte net1 poi net2), n2n1 (tutte "
                         "net2 poi net1), random (shuffle riproducibile "
                         "pilotato da --seed)")
    ap.add_argument("--wildcard-pos", choices=["tail", "head", "mixed"],
                    default="tail",
                    help="posizione delle wildcard /22: tail (in coda), head "
                         "(in testa), mixed (mescolate a caso fra gli ACCEPT). "
                         "Il log di default-drop resta comunque sempre ultimo.")
    ap.add_argument("--wildcard-action", choices=["deny", "accept"],
                    default="deny",
                    help="azione delle regole wildcard /22: deny (DROP, storico) "
                         "oppure accept (ACCEPT, per osservare cosa passa davvero "
                         "attraverso FW1). In stile pairs il LOG resta sempre "
                         "presente; con accept il prefisso diventa 'FW-WILD-OK '.")
    ap.add_argument("--net-split", default=None,
                    help="regole ACCEPT per net: 'N1,N2' (es. 100,450). "
                         "Se impostato, --limit non governa piu' gli ACCEPT")
    ap.add_argument("--net-ratio", default=None,
                    help="percentuale net1,net2 (es. 25,75): usa --limit come "
                         "TOTALE desiderato e calcola da solo lo split ACCEPT. "
                         "Mutuamente esclusivo con --net-split")
    ap.add_argument("--wildcard-rules", type=int, default=None,
                    help="numero di regole wildcard /22 (default: 48 = 24 porte "
                         "LOG+azione). Con --wildcard-style drop ogni regola e' "
                         "un'azione secca su una porta diversa (max 50 porte)")
    ap.add_argument("--wildcard-style", choices=["pairs", "drop"],
                    default="pairs",
                    help="pairs = coppie LOG+azione (storico); drop = solo azione "
                         "(DROP o ACCEPT a seconda di --wildcard-action)")
    ap.add_argument("--no-final-log", action="store_true",
                    help="omette la riga finale di LOG default-drop "
                         "('FW-DROP-DEF'): la policy FORWARD DROP scarta "
                         "comunque, ma senza log. Il totale scende di 1")
    args = ap.parse_args()

    rng = random.Random(args.seed)

    if args.net_split and args.net_ratio:
        ap.error("usa --net-split OPPURE --net-ratio, non entrambi")

    # n_wild va calcolato PRIMA: serve a --net-ratio per derivare lo split.
    if args.wildcard_rules is not None:
        n_wild = args.wildcard_rules
    elif args.wildcard_style == "drop":
        n_wild = len(INSECURE_WILDCARD)
    else:
        n_wild = 2 * len(INSECURE_WILDCARD)

    # Riga finale di LOG default-drop: presente salvo --no-final-log.
    n_final = 0 if args.no_final_log else 1

    net_split = None
    if args.net_split:
        try:
            p1, p2 = (int(x) for x in args.net_split.split(","))
            net_split = (p1, p2)
        except ValueError:
            ap.error("--net-split formato N1,N2 (es. 100,450)")
    elif args.net_ratio:
        # --limit = TOTALE desiderato; il budget ACCEPT esclude wildcard + final.
        try:
            r1, r2 = (float(x) for x in args.net_ratio.split(","))
        except ValueError:
            ap.error("--net-ratio formato R1,R2 (es. 25,75)")
        if r1 < 0 or r2 < 0 or (r1 + r2) == 0:
            ap.error("--net-ratio: proporzioni non valide (somma > 0)")
        accept_budget = max(2, args.limit - n_wild - n_final)
        n1 = round(accept_budget * r1 / (r1 + r2))
        n2 = accept_budget - n1
        net_split = (n1, n2)
        print(f"[i] --net-ratio {args.net_ratio} su totale ~{args.limit}: "
              f"net-split={n1},{n2} (ACCEPT={accept_budget}, "
              f"wildcard={n_wild}, +{n_final} final)", file=sys.stderr)

    cand_target = max(net_split) if net_split else None
    net1_entries, F = build_net1(args.limit, args.seed, args.variants,
                                 n_wild=n_wild, n1_target=cand_target)

    # Liste per net (asimmetriche con --net-split, mirror 1:1 altrimenti).
    if net_split is None:
        list1, list2 = net1_entries, net1_entries
    else:
        if len(net1_entries) < max(net_split):
            print(f"[!] candidati insufficienti ({len(net1_entries)}) per "
                  f"--net-split {args.net_split}: alza --variants",
                  file=sys.stderr)
        list1 = net1_entries[:net_split[0]]
        list2 = net1_entries[:net_split[1]]

    # Costruzione delle coppie (net1, net2) speculari.
    accept_rules = []  # tuple per assert_no_shadow
    accept_out = []    # (tag, line, comment_descr)

    def add_accept(e, tag):
        dst = e["dst"] if tag == "net1" else mirror(e["dst"])
        accept_rules.append((SRC, dst, "udp", e["port"]))
        accept_out.append((tag, emit_line(SRC, dst, "udp", e["port"]),
                           f"{e['descr']}-{e['zone']}-to-{dst}"))

    if args.order == "grouped":
        # Per ogni servizio: prima le net1, poi le net2.
        for name, port, descr, mode, zone in SERVICES:
            for e in [x for x in list1 if x["name"] == name]:
                add_accept(e, "net1")
            for e in [x for x in list2 if x["name"] == name]:
                add_accept(e, "net2")
    elif args.order == "mixed":
        # v6: interleaving PROPORZIONALE al rapporto |net1|:|net2|
        # (fusione tipo Bresenham, deterministica, NIENTE RNG).
        # A ogni passo viene emessa la net la cui frazione gia' emessa e'
        # rimasta indietro rispetto al rapporto target; il confronto
        # (i+1)*n2 <= (j+1)*n1 e' il cross-multiply intero di
        # (i+1)/n1 <= (j+1)/n2 (evita i float).
        #   - 138/412 -> n1 n2 n2 n2 n1 n2 n2 n2 ... (prima sempre net1, poi proporzionale)
        #   - liste uguali -> n1 n2 n1 n2 ... (identico al mixed di v5)
        n1_len, n2_len = len(list1), len(list2)
        # La prima regola e' SEMPRE verso net1 (se disponibile).
        if n1_len > 0:
            add_accept(list1[0], "net1")
        i, j = (1 if n1_len > 0 else 0), 0
        while i < n1_len or j < n2_len:
            if j >= n2_len or (i < n1_len and (i + 1) * n2_len <= (j + 1) * n1_len):
                add_accept(list1[i], "net1")
                i += 1
            else:
                add_accept(list2[j], "net2")
                j += 1
    elif args.order == "n1n2":
        for e in list1:
            add_accept(e, "net1")
        for e in list2:
            add_accept(e, "net2")
    elif args.order == "n2n1":
        for e in list2:
            add_accept(e, "net2")
        for e in list1:
            add_accept(e, "net1")
    else:  # random: shuffle riproducibile pilotato da --seed
        todo = [(e, "net1") for e in list1] + [(e, "net2") for e in list2]
        rng.shuffle(todo)
        for e, tag in todo:
            add_accept(e, tag)

    # Verifica anti-shadow (deve essere vuota per costruzione).
    conflicts = assert_no_shadow(accept_rules)
    if conflicts:
        print(f"[!] ATTENZIONE: {len(conflicts)} shadowed rules rilevate!",
              file=sys.stderr)
        for c in conflicts[:10]:
            print("    ", c, file=sys.stderr)

    # Wildcard /22 (coprono ENTRAMBE le net): numero, stile e AZIONE parametrici.
    WILDCARD_DST = "10.0.0.0/22"
    all_wild = INSECURE_WILDCARD + EXTRA_WILDCARD

    # --wildcard-action: deny -> DROP (storico) ; accept -> ACCEPT (vedo cosa passa)
    if args.wildcard_action == "accept":
        wild_target = "ACCEPT"
        wild_log_prefix = "FW-WILD-OK "
        action_tag = "accept"
    else:
        wild_target = "DROP"
        wild_log_prefix = "FW-INSEC "
        action_tag = "drop"

    if args.wildcard_style == "drop":
        n_ports = n_wild
    else:  # pairs: ogni porta = LOG+azione
        if n_wild % 2:
            print(f"[!] --wildcard-rules {n_wild} dispari con style=pairs: "
                  f"emetto {n_wild - 1} regole", file=sys.stderr)
        n_ports = n_wild // 2

    if n_ports > len(all_wild):
        print(f"[!] richieste {n_ports} porte wildcard, disponibili "
              f"{len(all_wild)}: tronco", file=sys.stderr)
        n_ports = len(all_wild)

    wild_units = []  # unita' da tenere adiacenti (coppia LOG+azione o azione singola)
    for proto, port, name in all_wild[:n_ports]:
        if args.wildcard_style == "pairs":
            wild_units.append([
                ("wildcard",
                 f'-A FORWARD -d {WILDCARD_DST} -p {proto} -m {proto} --dport {port} '
                 f'-m limit --limit 5/min -j LOG --log-prefix "{wild_log_prefix}"',
                 f"log-{name}"),
                ("wildcard",
                 f'-A FORWARD -d {WILDCARD_DST} -p {proto} -m {proto} --dport {port} '
                 f'-j {wild_target}',
                 f"{action_tag}-{name}"),
            ])
        else:
            wild_units.append([
                ("wildcard",
                 f'-A FORWARD -d {WILDCARD_DST} -p {proto} -m {proto} --dport {port} '
                 f'-j {wild_target}',
                 f"{action_tag}-{name}"),
            ])

    wildcard_out = [row for u in wild_units for row in u]
    final_out = []
    if not args.no_final_log:
        final_out = [("final",
            '-A FORWARD -m limit --limit 10/min -j LOG --log-prefix "FW-DROP-DEF "',
            "log-default-drop")]

    # Posizione delle wildcard (il default-drop log, se presente, resta SEMPRE ultimo).
    if args.wildcard_pos == "mixed":
        # shuffle per unita': le coppie LOG+azione restano adiacenti
        mix = [[row] for row in accept_out] + wild_units
        rng.shuffle(mix)
        all_entries = [row for u in mix for row in u] + final_out
    elif args.wildcard_pos == "head":
        all_entries = wildcard_out + accept_out + final_out
    else:  # tail
        all_entries = accept_out + wildcard_out + final_out

    # net-split effettivo per header/riepilogo (v5 con --net-ratio diceva 'mirror')
    split_desc = f"{net_split[0]},{net_split[1]}" if net_split else "mirror"

    now = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    header = [
        f"# Generated by gen_fw_rules_v6.py on {now}",
        "# REDIAL ruleset v6 - src=10.0.0.0/24, dst net1(10.0.1)/net2(10.0.2),",
        f"# solo UDP, nessuna shadowed rule. order={args.order} "
        f"wildcard={args.wildcard_pos}/{args.wildcard_style}/{args.wildcard_action} "
        f"net-split={split_desc}",
        "*filter",
        ":INPUT ACCEPT [0:0]",
        ":FORWARD DROP [0:0]",
        ":OUTPUT ACCEPT [0:0]",
    ]

    out = []
    counts = {}
    for i, (tag, line, descr) in enumerate(all_entries, start=1):
        rid = f"R{i:04d}"
        out.append(f'{line} -m comment --comment "{rid} [REDIAL:{tag}] {descr}"')
        counts[tag] = counts.get(tag, 0) + 1

    text = "\n".join(header + out + ["COMMIT", f"# Completed on {now}", ""])
    if args.output == "-":
        print(text)
    else:
        with open(args.output, "w") as fh:
            fh.write(text)
        breakdown = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print(f"[+] {len(out)} regole scritte in {args.output} "
              f"(order={args.order}, wildcard={args.wildcard_pos}/"
              f"{args.wildcard_style}/{args.wildcard_action}, "
              f"net-split={split_desc}, "
              f"limit={args.limit}, seed={args.seed}, "
              f"host/servizio={F}; {breakdown}; shadowed={len(conflicts)})",
              flush=True)


if __name__ == "__main__":
    main()
