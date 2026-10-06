#!/usr/bin/env python3
"""gen_packets_v2.py - Generatore deterministico di vettori di pacchetti per il banco REDIAL.

v2 - supporto ai ruleset v5 (--wildcard-action accept):
  * porte wildcard riconosciute dal tag [REDIAL:wildcard] con target DROP o
    ACCEPT (la v1 matchava solo -j DROP: con la v5 in accept non generava
    NESSUN pacchetto wildcard);
  * il campo `verdict` dei pacchetti wildcard riflette l'azione REALE della
    regola (ACCEPT/DROP): il check di sigma_simulate.py torna a 0 mismatch;
  * su ruleset v4 (wildcard DROP) output bit-per-bit identico alla v1.

Legge il ruleset prodotto da gen_fw_rules_v4/v5.py (flag -r/--rules) e genera
DUE vettori di pacchetti UDP (net1 = 10.0.1.0/24, net2 = 10.0.2.0/24) in modo
che ogni pacchetto MATCHI una regola del firewall (src in 10.0.0.0/24, proto
UDP, dport del catalogo, dst concreto dentro la destinazione della regola).
"""
import argparse
import ipaddress
import json
import random
import re
import sys
from collections import Counter

SRC_NET = "10.0.0.0/24"
NET1 = "10.0.1.0/24"
NET2 = "10.0.2.0/24"
RESERVED_OCTETS = {0, 1, 2, 3, 255}

RE_ACCEPT = re.compile(
    r'-A FORWARD -s (?P<src>\S+) -d (?P<dst>\S+) -p udp -m udp --dport (?P<dport>\d+) -j ACCEPT'
)
# v2: le wildcard /22 non hanno -s e possono essere DROP (v4) o ACCEPT (v5).
# Le righe LOG delle coppie hanno "-m limit ... -j LOG" e quindi non matchano.
RE_WILD = re.compile(
    r'-A FORWARD -d (?P<dst>\S+) -p udp -m udp --dport (?P<dport>\d+) -j (?P<target>ACCEPT|DROP)\b'
)
RE_COMMENT = re.compile(r'--comment "(?P<rid>R\d+) \[REDIAL:(?P<tag>\w+)\] (?P<label>[^"]*)"')


class Rule:
    __slots__ = ("rid", "tag", "dport", "label", "dst_cidr", "hosts")

    def __init__(self, rid, tag, dport, label, dst_cidr):
        self.rid = rid
        self.tag = tag
        self.dport = dport
        self.label = label
        self.dst_cidr = dst_cidr
        net = ipaddress.ip_network(dst_cidr, strict=False)
        if net.prefixlen == 32:
            self.hosts = [str(net.network_address)]
        else:
            self.hosts = [
                str(h) for h in net.hosts()
                if int(str(h).split(".")[-1]) not in RESERVED_OCTETS
            ]
            if not self.hosts:
                self.hosts = [str(h) for h in net.hosts()]


def parse_rules(path):
    """Ritorna (accepts, wildcards) con wildcards = {dport: target} ordinato per porta."""
    accepts = {"net1": [], "net2": []}
    wildcards = {}
    with open(path) as fh:
        for line in fh:
            line = line.rstrip("\n")
            cm = RE_COMMENT.search(line)
            if not cm:
                continue
            tag = cm.group("tag")
            if tag in accepts:
                ma = RE_ACCEPT.search(line)
                if ma:
                    accepts[tag].append(Rule(
                        cm.group("rid"), tag, int(ma.group("dport")),
                        cm.group("label"), ma.group("dst"),
                    ))
            elif tag == "wildcard":
                mw = RE_WILD.search(line)
                if mw:  # la riga LOG della coppia non matcha: corretto ignorarla
                    wildcards[int(mw.group("dport"))] = mw.group("target")
    return accepts, dict(sorted(wildcards.items()))


def even_counts(total, n_buckets):
    if n_buckets == 0:
        return []
    base, rem = divmod(total, n_buckets)
    return [base + (1 if i < rem else 0) for i in range(n_buckets)]


def host_pool(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    return [str(h) for h in net.hosts()
            if int(str(h).split(".")[-1]) not in RESERVED_OCTETS]


def make_payload(seq, size, fixed_hex):
    if fixed_hex is not None:
        return fixed_hex
    seqb = (seq & 0xFFFFFFFF).to_bytes(4, "big")
    if size <= 4:
        return seqb[:size].hex()
    filler = bytes((seq + k) & 0xFF for k in range(size - 4))
    return (seqb + filler).hex()


def build_vector(net_tag, dst_net, rules, wildcards, args, rng):
    if not rules:
        sys.exit(f"[err] nessuna regola ACCEPT trovata per {net_tag}")

    n_wild = round(args.count * args.wildcard_frac) if wildcards else 0
    n_accept = args.count - n_wild

    if args.src == "sweep":
        srcs = host_pool(SRC_NET)
    else:
        srcs = [args.src]

    payload_sizes = [int(x) for x in str(args.payload_bytes).split(",") if x != ""]
    fixed_hex = args.payload_hex.replace(" ", "") if args.payload_hex else None

    targets = []
    for cnt, rule in zip(even_counts(n_accept, len(rules)), rules):
        targets.extend([("accept", rule)] * cnt)
    if n_wild:
        ports = list(wildcards.items())  # gia' ordinate per porta (deterministico)
        for cnt, item in zip(even_counts(n_wild, len(ports)), ports):
            targets.extend([("wild", item)] * cnt)

    rng.shuffle(targets)

    packets = []
    seen = set()
    whosts = host_pool(dst_net)
    for i, (kind, obj) in enumerate(targets, start=1):
        if kind == "accept":
            rule = obj
            dport = rule.dport
            dst = rng.choice(rule.hosts)
            verdict = "ACCEPT"
            rid = rule.rid
            label = rule.label
        else:
            dport, action = obj
            dst = rng.choice(whosts)
            verdict = action  # v2: azione REALE della regola wildcard (ACCEPT o DROP)
            rid = ""
            label = f"wildcard-{dport}"

        src = rng.choice(srcs)
        for _ in range(4):
            sport = rng.randint(args.sport_min, args.sport_max)
            key = (src, dst, sport, dport)
            if key not in seen:
                break
        seen.add(key)

        size = payload_sizes[(i - 1) % len(payload_sizes)]
        payload_hex = make_payload(i, size, fixed_hex)
        plen = len(payload_hex) // 2

        packets.append({
            "seq": i, "net": net_tag, "proto": "udp",
            "src": src, "sport": sport, "dst": dst, "dport": dport,
            "plen": plen, "verdict": verdict, "rule_id": rid,
            "label": label, "payload_hex": payload_hex,
        })
    return packets


CSV_FIELDS = ["seq", "net", "proto", "src", "sport", "dst", "dport",
              "plen", "verdict", "rule_id", "label", "payload_hex"]


def write_csv(path, packets):
    with open(path, "w") as fh:
        fh.write(",".join(CSV_FIELDS) + "\n")
        for p in packets:
            fh.write(",".join(str(p[k]) for k in CSV_FIELDS) + "\n")


def write_jsonl(path, packets):
    with open(path, "w") as fh:
        for p in packets:
            fh.write(json.dumps(p, separators=(",", ":")) + "\n")


def summarize(net_tag, packets):
    legit = sum(1 for p in packets if p["rule_id"])
    wild = Counter(p["verdict"] for p in packets if not p["rule_id"])
    rules_hit = len({p["rule_id"] for p in packets if p["rule_id"]})
    uniq5 = len({(p["src"], p["dst"], p["sport"], p["dport"]) for p in packets})
    uniqpkt = len({(p["src"], p["dst"], p["sport"], p["dport"], p["payload_hex"]) for p in packets})
    wild_str = " ".join(f"{k}={v}" for k, v in sorted(wild.items())) if wild else "0"
    return (f"  {net_tag}: {len(packets)} pkt | legit(ACCEPT)={legit} "
            f"wildcard[{wild_str}] | regole coperte={rules_hit} | "
            f"5-tuple uniche={uniq5} ({100*uniq5/len(packets):.2f}%) | "
            f"pacchetti unici={uniqpkt} ({100*uniqpkt/len(packets):.2f}%)")


def main():
    ap = argparse.ArgumentParser(description="Generatore vettori di pacchetti REDIAL v2 (net1/net2).")
    ap.add_argument("-r", "--rules", required=True)
    ap.add_argument("--out-net1", default="packets_net1.csv")
    ap.add_argument("--out-net2", default="packets_net2.csv")
    ap.add_argument("--count", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--wildcard-frac", type=float, default=0.05)
    ap.add_argument("--payload-bytes", default="4")
    ap.add_argument("--payload-hex", default=None)
    ap.add_argument("--src", default="10.0.0.1")
    ap.add_argument("--sport-min", type=int, default=1024)
    ap.add_argument("--sport-max", type=int, default=65535)
    ap.add_argument("--format", choices=["csv", "jsonl"], default="csv")
    args = ap.parse_args()

    accepts, wildcards = parse_rules(args.rules)
    rng = random.Random(args.seed)

    if not wildcards and args.wildcard_frac > 0:
        print("[!] nessuna porta wildcard trovata nel ruleset: vettori SENZA rumore "
              "(controlla i tag [REDIAL:wildcard] in fw1.rules)", file=sys.stderr)

    pkt1 = build_vector("net1", NET1, accepts["net1"], wildcards, args, rng)
    pkt2 = build_vector("net2", NET2, accepts["net2"], wildcards, args, rng)

    ext = ".jsonl" if args.format == "jsonl" else None
    out1 = args.out_net1 if ext is None else args.out_net1.rsplit(".", 1)[0] + ext
    out2 = args.out_net2 if ext is None else args.out_net2.rsplit(".", 1)[0] + ext
    writer = write_jsonl if args.format == "jsonl" else write_csv
    writer(out1, pkt1)
    writer(out2, pkt2)

    actions = ", ".join(sorted(set(wildcards.values()))) if wildcards else "n/d"
    print(f"[+] regole lette da {args.rules}: "
          f"net1={len(accepts['net1'])} ACCEPT, net2={len(accepts['net2'])} ACCEPT, "
          f"{len(wildcards)} porte wildcard (azione: {actions})")
    print(f"[+] scritti {out1} e {out2} (seed={args.seed}, formato={args.format})")
    print(summarize("net1", pkt1))
    print(summarize("net2", pkt2))


if __name__ == "__main__":
    main()
