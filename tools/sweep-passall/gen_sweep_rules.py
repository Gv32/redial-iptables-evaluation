#!/usr/bin/env python3
"""gen_sweep_rules.py - Ruleset "pass-all a posizione h" per il test del prof.

Non genera regole da zero: riusa come FILLER gli ACCEPT di un ruleset base
prodotto da gen_fw_rules_v5.py (che resta intatto). Per ogni h emette un file:
  * 1000 filler che NON matchano mai il probe (porte catalogo, tutte != 5000)
  * 1 pass-all inserita in posizione h  ->  totale esatto 1001 regole
  * policy FORWARD DROP, nessun final-log.
sigma atteso = h esatto (il probe matcha solo la pass-all).

Uso:
  python3 gen_fw_rules_v5.py -o base_sweep.rules --seed 42 \
      --net-split 500,500 --wildcard-rules 0 --order n1n2
  python3 gen_sweep_rules.py -r base_sweep.rules --positions 1:1001:50 -d rules_sweep/
"""
import argparse
import os
import re
import sys

PROBE_PORT = 5000   # porta del probe udpramp: NON deve esistere tra i filler
PASSALL = ('-A FORWARD -s 10.0.0.0/24 -j ACCEPT '
           '-m comment --comment "{rid} [SWEEP:passall] pass-all-probe"')

RE_ACCEPT = re.compile(r'-A FORWARD .*--dport (\d+) -j ACCEPT')
RE_TAG = re.compile(r'\[REDIAL:(net1|net2)\]')   # esclude wildcard e final-log
RE_RID = re.compile(r'"R\d{4} ')


def load_filler(path, n):
    out = []
    with open(path) as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not RE_TAG.search(line):
                continue
            m = RE_ACCEPT.search(line)
            if not m:
                continue
            if int(m.group(1)) == PROBE_PORT:
                sys.exit(f"[err] un filler usa la porta del probe ({PROBE_PORT})")
            out.append(line)
            if len(out) == n:
                break
    if len(out) < n:
        sys.exit(f"[err] servono {n} filler, trovati {len(out)}: "
                 "rigenera la base con --net-split 500,500 (o alza --variants)")
    return out


def renumber(line, i):
    return RE_RID.sub(f'"R{i:04d} ', line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-r", "--rules", required=True, help="ruleset base (filler)")
    ap.add_argument("-d", "--outdir", default="rules_sweep")
    ap.add_argument("--filler", type=int, default=1000)
    ap.add_argument("--positions", default="1:1001:50", help="start:stop:step")
    args = ap.parse_args()

    start, stop, step = (int(x) for x in args.positions.split(":"))
    positions = list(range(start, stop + 1, step))
    if positions[-1] != stop:
        positions.append(stop)

    filler = load_filler(args.rules, args.filler)
    os.makedirs(args.outdir, exist_ok=True)

    header = ["# gen_sweep_rules.py - pass-all a posizione h (test prof)",
              "*filter",
              ":INPUT ACCEPT [0:0]",
              ":FORWARD DROP [0:0]",
              ":OUTPUT ACCEPT [0:0]"]
    for h in positions:
        body = filler[:h - 1] + ["__PASSALL__"] + filler[h - 1:]
        lines = []
        for i, ln in enumerate(body, start=1):
            if ln == "__PASSALL__":
                lines.append(PASSALL.format(rid=f"R{i:04d}"))
            else:
                lines.append(renumber(ln, i))
        path = os.path.join(args.outdir, f"sweep_h{h:04d}.rules")
        with open(path, "w") as fh:
            fh.write("\n".join(header + lines + ["COMMIT", ""]))
        print(f"[+] {path}: {len(lines)} regole, pass-all in posizione {h} "
              f"(sigma atteso = {h})")


if __name__ == "__main__":
    main()
