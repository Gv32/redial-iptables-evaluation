#!/usr/bin/env python3
"""
sigma_collector_subnet.py - v2.1  (estende sigma_collector v1.3)

Novita' v2.1:
  * 'compare' calcola Gamma (eq. 5) e i limiti Gamma_M/av/m (eq. 10-12)
    sui sigma CON WILDCARD INCLUSE, che sono i sigma del paper: il paper
    (TIFS 2021, Sez. IV-A) definisce sigma_1^K e sigma_K+1^N come medie su
    TUTTI i pacchetti destinati a D_1^K / D_K+1^N, senza escludere il
    traffico che matcha regole wildcard;
  * rho "paper" calcolato includendo i pacchetti wildcard nel conteggio
    per destinazione (con f1=f2 coincide col rho legit);
  * la versione legit-only resta in output come scomposizione per classi
    di regole rilocabili (sezione B del compare).

Novita' v2.0 rispetto a v1.3:
  * sigma PER SUBNET che INCLUDONO le wildcard (oltre ai sigma legit-only
    del metodo attuale, stampati comunque per confronto);
  * attribuzione del contatore (condiviso) delle regole wildcard a net1/net2
    a partire da rho del sender e, opzionalmente, dalle frazioni wildcard
    reali lette dai vettori di pacchetti;
  * gestione corretta del \"leak\" del POST: i pacchetti wildcard verso net2
    cadono nello shortcut -d 10.0.2.0/24 -j ACCEPT (match solo sul dst) e non
    raggiungono piu' la regola wildcard di coda -> in POST tutto il contatore
    wildcard e' di net1, mentre le wildcard di net2 sono gia' dentro sigma_net2;
  * output a sezioni, leggibile a colpo d'occhio.

Scenario di riferimento: ruleset net1 - net2 - wildcard, wildcard in ACCEPT.
Funziona comunque con qualunque layout perche' l'attribuzione parte dai
contatori reali letti dalla chain.

Modello di costo (first matching strategy):
  - pkt che matcha la regola terminante in posizione assoluta p -> p regole;
  - pkt che cade nella policy di default -> tutte le N regole;
  - regole non terminanti (LOG, NFLOG, ...) ignorate.
"""

import argparse
import getpass
import json
import re
import subprocess
import sys
from datetime import datetime
from ipaddress import ip_network

TERMINATING = {"ACCEPT", "DROP", "REJECT", "RETURN"}
NON_TERMINATING = {"LOG", "NFLOG", "AUDIT", "MARK", "CONNMARK", "TRACE", "TEE", "CT"}


def parse_cli():
    p = argparse.ArgumentParser(
        description="Misura i sigma per subnet (con wildcard) pre/post REDIAL su FW1.")
    p.add_argument("--host", default="192.168.100.103",
                   help="IP management del FW (default: %(default)s = TS-P360/FW1)")
    p.add_argument("--user", default=getpass.getuser(), help="utente SSH")
    p.add_argument("-i", "--identity", default=None, help="chiave privata SSH")
    p.add_argument("--netns", default="FW", help="network namespace del firewall")
    p.add_argument("--chain", default="FORWARD", help="chain iptables")
    p.add_argument("--net1", default="10.0.1.0/24", help="subnet dn (non redistribuita)")
    p.add_argument("--net2", default="10.0.2.0/24", help="subnet d2 (redistribuita da REDIAL)")
    p.add_argument("--no-sudo", action="store_true", help="non anteporre 'sudo'")
    p.add_argument("--local", action="store_true", help="esegui iptables in locale (sul FW)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("zero", help="azzera i contatori della chain (PRIMA di ogni run)")
    c = sub.add_parser("collect", help="legge i contatori e calcola i sigma per subnet")
    c.add_argument("--post", action="store_true",
                   help="run post-REDIAL: cerca lo shortcut, ricava h, gestisce il leak")
    c.add_argument("--rho", type=float, default=None,
                   help="frazione di pacchetti verso net2 impostata sul sender; "
                        "se assente usa il rho misurato dai contatori legit")
    c.add_argument("--packets-net1", default=None,
                   help="vettore CSV net1 (per leggere la frazione wildcard reale f1)")
    c.add_argument("--packets-net2", default=None,
                   help="vettore CSV net2 (per leggere la frazione wildcard reale f2)")
    c.add_argument("-o", "--output", default=None, help="salva il risultato in JSON")
    k = sub.add_parser("compare", help="Gamma effettivo vs Gamma_M/Gamma_av/Gamma_m")
    k.add_argument("pre", help="JSON prodotto da 'collect' (run PRE)")
    k.add_argument("post", help="JSON prodotto da 'collect --post' (run POST)")
    k.add_argument("--rho", type=float, default=None,
                   help="forza rho (default: rho misurato nella run PRE)")
    return p.parse_args()


def run_ssh(a, remote_cmd):
    if a.local:
        cmd = ["sh", "-c", remote_cmd]
    else:
        cmd = ["ssh"]
        if a.identity:
            cmd += ["-i", a.identity]
        cmd += [f"{a.user}@{a.host}", remote_cmd]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        where = "comando locale" if a.local else "ssh"
        sys.exit(f"[ERRORE] {where} rc={r.returncode}: {r.stderr.strip()}")
    return r.stdout


def ipt(a, args_str):
    sudo = "" if a.no_sudo else "sudo "
    return run_ssh(a, f"{sudo}ip netns exec {a.netns} iptables {args_str}")


def parse_chain(text, chain):
    """Parsa l'output di: iptables -L <chain> -nvx --line-numbers"""
    policy, policy_pkts, rules = None, 0, []
    for line in text.splitlines():
        m = re.match(r"Chain\s+(\S+)\s+\(policy\s+(\S+)\s+(\d+)\s+packets", line)
        if m:
            if m.group(1) != chain:
                sys.exit(f"[ERRORE] chain inattesa nell'output: {m.group(1)}")
            policy, policy_pkts = m.group(2), int(m.group(3))
            continue
        t = line.split(None, 10)
        if len(t) < 10 or not t[0].isdigit():
            continue
        rest = t[10] if len(t) > 10 else ""
        cm = re.search(r"/\*\s*(.*?)\s*\*/", rest)
        comment = cm.group(1) if cm else ""
        tg = re.search(r"\[REDIAL:(\w+)\]", comment)
        rules.append(dict(pos=int(t[0]), pkts=int(t[1]), target=t[3],
                          dst=t[9], comment=comment,
                          tag=tg.group(1) if tg else None))
    if policy is None:
        sys.exit("[ERRORE] header della chain non trovato")
    return policy, policy_pkts, rules


def classify(rule, net1, net2):
    if rule["tag"] == "net1":
        return "net1"
    if rule["tag"] == "net2":
        return "net2"
    if rule["tag"] in ("wildcard", "final"):
        return "wildcard"
    try:
        d = ip_network(rule["dst"], strict=False)
    except ValueError:
        return "wildcard"
    if d.subnet_of(net2):
        return "net2"
    if d.subnet_of(net1):
        return "net1"
    return "wildcard"


def fmt(x):
    return f"{x:.3f}" if x is not None else "n/d"


def wildcard_fraction(path):
    """Frazione di pacchetti wildcard nel vettore (rule_id vuoto o label 'wildcard')."""
    total = wild = 0
    with open(path) as fh:
        header = fh.readline().rstrip("\n").split(",")
        try:
            i_rid = header.index("rule_id")
            i_lbl = header.index("label")
        except ValueError:
            sys.exit(f"[ERRORE] {path}: header CSV senza rule_id/label")
        for line in fh:
            cols = line.rstrip("\n").split(",")
            if len(cols) <= max(i_rid, i_lbl):
                continue
            total += 1
            if cols[i_rid].strip() == "" or cols[i_lbl].strip().startswith("wildcard"):
                wild += 1
    return (wild / total) if total else 0.0


def do_zero(a):
    ipt(a, f"-Z {a.chain}")
    policy, _, rules = parse_chain(ipt(a, f"-L {a.chain} -nvx --line-numbers"), a.chain)
    print(f"[OK] contatori azzerati su {a.host} ns={a.netns} chain={a.chain} "
          f"({len(rules)} regole, policy {policy}). Pronto per la run.")


def do_collect(a):
    policy, policy_pkts, rules = parse_chain(
        ipt(a, f"-L {a.chain} -nvx --line-numbers"), a.chain)
    net1, net2 = ip_network(a.net1), ip_network(a.net2)
    n_rules = len(rules)
    stats = {k: dict(pkts=0, weight=0, pos_sum=0, n=0)
             for k in ("net1", "net2", "wildcard")}
    for r in rules:
        if r["target"] in NON_TERMINATING:
            continue
        if r["target"] not in TERMINATING and r["pkts"] > 0:
            print(f"[WARN] target '{r['target']}' (pos {r['pos']}): non gestito, "
                  f"trattato come terminante", file=sys.stderr)
        c = classify(r, net1, net2)
        stats[c]["pkts"] += r["pkts"]
        stats[c]["weight"] += r["pkts"] * r["pos"]
        stats[c]["pos_sum"] += r["pos"]
        stats[c]["n"] += 1

    tot_pkts = sum(s["pkts"] for s in stats.values()) + policy_pkts
    tot_weight = sum(s["weight"] for s in stats.values()) + policy_pkts * n_rules
    sigma_overall = tot_weight / tot_pkts if tot_pkts else None

    def avg(s):
        return s["weight"] / s["pkts"] if s["pkts"] else None

    def expected(s):
        return s["pos_sum"] / s["n"] if s["n"] else None

    sigma_net1_legit = avg(stats["net1"])
    sigma_net2_legit = avg(stats["net2"])

    # aggregati della classe wildcard (contatori esatti)
    cw = stats["wildcard"]["pkts"]
    ww = stats["wildcard"]["weight"]

    # rho
    unamb = stats["net1"]["pkts"] + stats["net2"]["pkts"]
    rho_meas = stats["net2"]["pkts"] / unamb if unamb else None
    rho = a.rho if a.rho is not None else rho_meas

    # frazioni wildcard reali dai vettori (opzionali)
    f1 = f2 = None
    if a.packets_net1 and a.packets_net2:
        f1 = wildcard_fraction(a.packets_net1)
        f2 = wildcard_fraction(a.packets_net2)

    # shortcut / h (POST)
    h = None
    if a.post:
        for r in rules:
            try:
                if r["target"] == "ACCEPT" and ip_network(r["dst"], strict=False) == net2:
                    h = r["pos"]
                    break
            except ValueError:
                continue
        if h is None:
            print("[WARN] shortcut verso net2 non trovato: REDIAL e' stato applicato?",
                  file=sys.stderr)

    # quota della classe wildcard attribuita a net2
    if a.post:
        # leak: le wildcard verso net2 sono nello shortcut (gia' in net2);
        # la wildcard di coda raccoglie solo net1.
        share2 = 0.0
    elif rho is None:
        share2 = None
    elif f1 is not None and f2 is not None:
        den = (1 - rho) * f1 + rho * f2
        share2 = (rho * f2 / den) if den else None
    else:
        share2 = rho  # frazioni wildcard uguali tra le due net

    sigma_net1_incl = sigma_net2_incl = None
    cw1 = cw2 = None
    if share2 is not None:
        cw2 = cw * share2
        cw1 = cw * (1 - share2)
        ww2 = ww * share2
        ww1 = ww * (1 - share2)
        c1 = stats["net1"]["pkts"] + cw1
        c2 = stats["net2"]["pkts"] + cw2
        w1 = stats["net1"]["weight"] + ww1
        w2 = stats["net2"]["weight"] + ww2
        sigma_net1_incl = w1 / c1 if c1 else None
        sigma_net2_incl = w2 / c2 if c2 else None

    res = dict(
        timestamp=datetime.now().astimezone().isoformat(timespec="seconds"),
        host=a.host, netns=a.netns, chain=a.chain,
        mode="post" if a.post else "pre",
        n_rules=n_rules, policy=policy, policy_pkts=policy_pkts,
        pkts=dict(net1=stats["net1"]["pkts"], net2=stats["net2"]["pkts"],
                  wildcard=cw, total=tot_pkts),
        rho_measured=rho_meas, rho_used=rho, wildcard_share_net2=share2,
        h=h,
        sigma_net1=sigma_net1_legit, sigma_net2=sigma_net2_legit,
        sigma_net1_incl=sigma_net1_incl, sigma_net2_incl=sigma_net2_incl,
        sigma_overall=sigma_overall,
        expected_net1=expected(stats["net1"]), expected_net2=expected(stats["net2"]),
        rules_net1=stats["net1"]["n"], rules_net2=stats["net2"]["n"],
        rules_wildcard=stats["wildcard"]["n"],
    )

    lbl = "POST" if a.post else "PRE"
    print(f"=== sigma_collector_subnet v2.1 [{lbl}]  {a.host}  ns={a.netns}  chain={a.chain} ===")
    print(f"|fw|={n_rules} regole   policy {policy} ({policy_pkts} pkt)")
    print(f"pkt terminati: net1={stats['net1']['pkts']}  net2={stats['net2']['pkts']}  "
          f"wildcard={cw}  policy={policy_pkts}  tot={tot_pkts}")
    if tot_pkts == 0:
        sys.exit("[ERRORE] nessun pacchetto contato: contatori azzerati o run non partita?")

    def line(label, meas, exp_v):
        extra = ""
        if meas is not None and exp_v is not None:
            extra = f"   [atteso {exp_v:.3f}  delta {meas - exp_v:+.3f}]"
        print(f"   {label} = {fmt(meas)}{extra}")

    print("\n-- (1) Metodo attuale: sigma per subnet, wildcard ESCLUSE --")
    line("sigma_net1 (legit)", sigma_net1_legit, res["expected_net1"])
    line("sigma_net2 (legit)", sigma_net2_legit, res["expected_net2"])

    print("\n-- (2) Sigma per subnet, wildcard INCLUSE (= sigma del paper, eq. 3-12) --")
    if sigma_net1_incl is None and sigma_net2_incl is None:
        print("   [n/d] manca rho per ripartire le wildcard del PRE: passa --rho")
    else:
        if rho is not None:
            src = "forzato --rho" if a.rho is not None else "misurato dai contatori legit"
            print(f"   rho = {fmt(rho)} ({src})")
        if a.post:
            print(f"   POST: le wildcard verso net2 cadono nello shortcut (pos h={h}) e "
                  f"sono gia' dentro sigma_net2; la wildcard di coda = sole wildcard di net1.")
        else:
            if f1 is not None:
                print(f"   frazioni wildcard dai vettori: net1={f1:.4f}  net2={f2:.4f}")
            print(f"   contatore wildcard ripartito: net1={cw1:.0f} ({100*(1-share2):.1f}%)  "
                  f"net2={cw2:.0f} ({100*share2:.1f}%)")
        print(f"   sigma_net1 (incl. wildcard) = {fmt(sigma_net1_incl)}")
        print(f"   sigma_net2 (incl. wildcard) = {fmt(sigma_net2_incl)}")

    print("\n-- (3) Totale firewall --")
    print(f"   sigma_overall (tutti i pkt, esatto) = {fmt(sigma_overall)}")
    if a.post and h is not None:
        ok = sigma_net2_legit is not None and abs(sigma_net2_legit - h) < 1.0
        print(f"   shortcut net2 in posizione h = {h}  "
              f"({'OK: sigma_net2 ~ h' if ok else 'controlla: sigma_net2 != h'})")

    if a.output:
        with open(a.output, "w") as f:
            json.dump(res, f, indent=2)
        print(f"[OK] risultato salvato in {a.output}")


def do_compare(a):
    with open(a.pre) as f:
        pre = json.load(f)
    with open(a.post) as f:
        post = json.load(f)
    if pre.get("mode") != "pre" or post.get("mode") != "post":
        print("[WARN] i file non sembrano una coppia pre/post coerente", file=sys.stderr)
    rho = a.rho if a.rho is not None else pre.get("rho_used")
    s1K, sK1N, s1N = pre.get("sigma_net2"), pre.get("sigma_net1"), pre.get("sigma_overall")
    s1N_post, sK1N_post = post.get("sigma_overall"), post.get("sigma_net1")
    s1K_i, sK1N_i = pre.get("sigma_net2_incl"), pre.get("sigma_net1_incl")
    s1K_i_post, sK1N_i_post = post.get("sigma_net2_incl"), post.get("sigma_net1_incl")
    N, Nh = pre["n_rules"], post["n_rules"]
    h = post.get("h") or post.get("sigma_net2")
    missing = [n for n, v in [("rho", rho), ("sigma_1^N pre", s1N),
                              ("sigma_1^K pre", s1K), ("sigma_K+1^N pre", sK1N),
                              ("sigma_1^N post", s1N_post), ("h", h)] if v is None]
    if missing:
        sys.exit(f"[ERRORE] valori mancanti per il confronto: {', '.join(missing)}")

    # rho "paper": frazione di pacchetti DESTINATI a net2, wildcard incluse
    rho_paper = rho
    share2 = pre.get("wildcard_share_net2")
    pk = pre.get("pkts") or {}
    if a.rho is None and share2 is not None:
        denom = pk.get("net1", 0) + pk.get("net2", 0) + pk.get("wildcard", 0)
        if denom:
            rho_paper = (pk.get("net2", 0) + pk.get("wildcard", 0) * share2) / denom

    def bounds_and_gammas(sk1n_val, rho_val, s1n_pre_val):
        best = sk1n_val - (N - Nh)     # eq. (6)  regole ereditate in testa
        unif = sk1n_val * Nh / N       # eq. (7)  distribuzione uniforme
        worst = sk1n_val + 1           # eq. (8)  regole ereditate in coda

        def g(shat):
            return s1n_pre_val / (h * rho_val + shat * (1 - rho_val))

        return g(best), g(unif), g(worst)

    print("=== confronto PRE vs POST (FW1) ===")
    src = "(forzato da --rho)" if a.rho is not None else "(misurato nella run PRE)"
    print(f"rho legit = {fmt(rho)} {src}   rho paper incl. wildcard = {fmt(rho_paper)}")
    print(f"|fw1| = {N}   |fw1^| = {Nh}   h = {h}")

    print("\n-- (A) Sigma del paper (per destinazione, wildcard INCLUSE) --")
    if None in (s1K_i, sK1N_i, sK1N_i_post):
        print("   [n/d] JSON senza sigma incl. wildcard: rigenera i file con collect v2.x")
    else:
        s1N_i = s1K_i * rho_paper + sK1N_i * (1 - rho_paper)          # eq. (3)
        s1N_i_post = h * rho_paper + sK1N_i_post * (1 - rho_paper)    # eq. (4)
        gamma_paper = s1N_i / s1N_i_post                              # eq. (5)
        gM, gav, gm = bounds_and_gammas(sK1N_i, rho_paper, s1N_i)
        print(f"PRE :  sigma_1^K={fmt(s1K_i)}   sigma_K+1^N={fmt(sK1N_i)}   "
              f"sigma_1^N={fmt(s1N_i)}  (eq.3)")
        print(f"POST:  sigma^_1^K={fmt(s1K_i_post)} (atteso = h = {h})   "
              f"sigma^_K+1^N={fmt(sK1N_i_post)}   sigma^_1^N={fmt(s1N_i_post)}  (eq.4)")
        print(f"Gamma paper (eq.5) = {gamma_paper:8.3f}   <-- confronto coi limiti")
        print(f"Gamma_M  (eq.10) = {gM:8.3f}   [migliore: regole ereditate in testa]")
        print(f"Gamma_av (eq.11) = {gav:8.3f}   [distribuzione uniforme]")
        print(f"Gamma_m  (eq.12) = {gm:8.3f}   [peggiore: regole ereditate in coda]")
        if gm - 1e-6 <= gamma_paper <= gM + 1e-6:
            print("[OK] Gamma paper dentro l'intervallo teorico [Gamma_m, Gamma_M]")
        else:
            print("[ATTENZIONE] Gamma paper FUORI dall'intervallo teorico!")

    print("\n-- (B) Scomposizione legit-only (classi net1/net2, wildcard ESCLUSE) --")
    s1N_legit = s1K * rho + sK1N * (1 - rho)                          # eq. (3) legit
    s1N_post_pred = h * rho + (sK1N_post or 0) * (1 - rho)            # eq. (4) legit
    gamma_legit = s1N_legit / s1N_post_pred
    gM_l, gav_l, gm_l = bounds_and_gammas(sK1N, rho, s1N_legit)
    print(f"PRE :  sigma_1^K={fmt(s1K)}   sigma_K+1^N={fmt(sK1N)}   sigma_1^N={fmt(s1N_legit)}")
    print(f"POST:  sigma^_1^K={fmt(post.get('sigma_net2'))}   "
          f"sigma^_K+1^N={fmt(sK1N_post)}   sigma^_1^N={fmt(s1N_post_pred)}")
    print(f"Gamma legit = {gamma_legit:8.3f}   [range legit: {gm_l:.3f} .. {gM_l:.3f}, "
          f"Gamma_av {gav_l:.3f}]")

    print("\n-- (C) Totale misurato (tutti i pkt, incl. policy) --")
    print(f"sigma_1^N PRE = {fmt(s1N)}   sigma^_1^N POST = {fmt(s1N_post)}   "
          f"Gamma totale = {s1N / s1N_post:8.3f}")


def main():
    a = parse_cli()
    if a.cmd == "zero":
        do_zero(a)
    elif a.cmd == "collect":
        do_collect(a)
    elif a.cmd == "compare":
        do_compare(a)


if __name__ == "__main__":
    main()
