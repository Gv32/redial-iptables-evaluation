"""
redial_v5.2.py — REDIAL allineato a Durante et al., TIFS 2021.

Unione di due linee di fix che erano rimaste su rami separati:

  ★ da redial_v5:   salto fw2,i^.FORWARD → REDIAL_A_<j> con match per
                    interfaccia di ingresso (-i <iface>) invece che per
                    sorgente (-s d0): cattura TUTTO il traffico che ha
                    attraversato fw1, anche da sorgenti ≠ d0 (es. dn).
                    Opt-in: se fw2_upstream_ifaces è None, torna al -s d0.

  ★ da redial_v4.2: decide_inheritance() ritorna SEMPRE (True, True).
                    L'ottimizzazione per-policy di v3/v4/v5 ("se la default
                    di fw2 copre già una classe, non spostarla") viola il
                    first-match-wins — vedi il docstring della funzione.

Punti fermi (invariati):
  - shortcut -d d2,j -j ACCEPT in fw1^, inserita alla prima regola spostata;
  - ACCEPT ereditate → -j RETURN dentro REDIAL_A_<j>;
  - DENY ereditate   → -j DROP / REJECT;
  - target non-terminanti (LOG, MARK, ...) con log_strategy ∈ {move, keep, duplicate};
  - niente Translation Table, niente goto numerici: output 100%
    iptables-restore-compatibile.

Dipendenza: RedialUtils.py v4.2 (campo `in_iface` su Rule + emit `-i <iface>`
nel serializer). Codice completo nella pagina del fix v5.
"""

import ipaddress
from copy import deepcopy
from typing import List, Literal, Optional, Tuple

from redialUtils import (
    Firewall, Table, Rule, ChainDef, Counters,
    parse_iptables_xml_to_firewall, firewall_to_iptables_save,
    convert_rules_txt_to_xml,
)


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

_NON_TERMINATING = {
    "LOG", "NFLOG", "AUDIT", "MARK", "CONNMARK", "TRACE", "TEE", "CT",
}


def _norm(action: Optional[str]) -> str:
    return (action or "").strip().upper()


def _is_allow(action: Optional[str]) -> bool:
    return _norm(action) in ("ACCEPT", "ALLOW")


def _is_deny(action: Optional[str]) -> bool:
    return _norm(action) in ("DROP", "DENY", "REJECT")


def _is_nonterminating(action: Optional[str]) -> bool:
    return _norm(action) in _NON_TERMINATING


def get_forward_policy(fw: Firewall) -> str:
    for table in fw.tables:
        if table.table_name != "filter":
            continue
        for cd in table.chain_defs:
            if cd.chain_id == "FORWARD":
                return _norm(cd.ext_chain_policy) or "DROP"
    return "DROP"


def decide_inheritance(fw1_policy: str, fw2_policy: str) -> Tuple[bool, bool]:
    """
    ★ da v4.2: si DEVONO sempre spostare sia ACCEPT che DENY.

    L'ottimizzazione di v3/v4/v5 "se la default policy di fw2 copre già
    una delle due classi, non spostarla" è semanticamente errata perché
    iptables applica first-match-wins e l'ordine relativo delle regole
    ACCEPT/DENY in fw1 è significativo. Esempio:

        -A FORWARD -s 10.0.0.5 -j ACCEPT        ← eccezione esplicita
        -A FORWARD -s 10.0.0.0/24 -j DROP
        default: DROP

    fw1 originale: il pacchetto da 10.0.0.5 viene ACCETTATO dalla prima
    regola; le successive non lo riguardano.

    Con la logica a 4 casi (fw2 default = ACCEPT → move_accept = False),
    in REDIAL_A_<j> finisce SOLO la regola DROP -s 10.0.0.0/24 → il
    pacchetto da 10.0.0.5 viene erroneamente droppato.

    Simmetricamente, omettere le DENY nel caso (ACCEPT, ACCEPT) può
    trasformare un DROP specifico in un ACCEPT (perché l'ACCEPT di
    subnet che lo precedeva continua ad esserci, e l'unico filtro che
    lo droppava è stato omesso).

    L'unica scelta sicura è spostare sempre entrambe le classi.
    """
    return (True, True)


def _make_custom_chain(name: str) -> ChainDef:
    return ChainDef(
        colon=":",
        chain_id=name,
        ext_chain_policy="-",
        counters=Counters(packets=0, bytes=0),
    )


# ──────────────────────────────────────────────────────────────────────
# Algoritmo REDIAL — v5.2
# ──────────────────────────────────────────────────────────────────────

def redial(
    fw1: Firewall,
    fw2_list: List[Firewall],
    d2_list: List[ipaddress.IPv4Network],
    d0: ipaddress.IPv4Network,
    dn: List[ipaddress.IPv4Network],
    custom_chain_prefix: str = "REDIAL_A_",
    log_strategy: Literal["move", "keep", "duplicate"] = "move",
    fw2_upstream_ifaces: Optional[List[Optional[str]]] = None,        # ★ da v5
):
    """
    fw2_upstream_ifaces : lista parallela a fw2_list. Ogni elemento è il
      nome dell'interfaccia (es. "veth-fw2-up") da cui arriva su fw2,j
      il traffico che ha attraversato fw1. Se None per un dato j (o se
      l'intera lista è None), si torna al match -s d0.
    """
    K = len(d2_list)
    assert len(fw2_list) == K, "fw2_list e d2_list devono avere la stessa lunghezza"
    assert log_strategy in ("move", "keep", "duplicate"), \
        f"log_strategy invalido: {log_strategy!r}"

    if fw2_upstream_ifaces is None:
        fw2_upstream_ifaces = [None] * K
    assert len(fw2_upstream_ifaces) == K, \
        "fw2_upstream_ifaces deve avere la stessa lunghezza di fw2_list"

    fw1_hat = Firewall()
    fw2_hat: List[Firewall] = [Firewall() for _ in range(K)]

    if not fw1.tables:
        return fw1_hat, fw2_hat

    orig_table = fw1.tables[0]
    fw1_policy = get_forward_policy(fw1)

    # ─── Costruzione di fw1^ + raccolta delle regole ereditate ────────
    fw1_new = Table(star="*", table_name=orig_table.table_name)
    fw1_new.chain_defs = deepcopy(orig_table.chain_defs)

    inherited: List[List[Rule]] = [[] for _ in range(K)]
    shortcut_inserted = False

    for r in orig_table.rules:
        dst = r.dst
        moved = False
        is_nonterm = _is_nonterminating(r.action)
        move_this = (not is_nonterm) or (log_strategy in ("move", "duplicate"))

        for j in range(K):
            if dst is None or dst.overlaps(d2_list[j]):
                if move_this:
                    inherited[j].append(deepcopy(r))
                moved = True

        if moved and not shortcut_inserted:
            shortcut_inserted = True
            for d in d2_list:
                fw1_new.rules.append(Rule(
                    chain="FORWARD", src=None, dst=d,
                    proto=None, sport=None, dport=None,
                    icmp_type=None, action="ACCEPT",
                ))

        keeps_in_fw1 = (dst is None) or any(dst.overlaps(x) for x in dn)
        if is_nonterm and log_strategy in ("keep", "duplicate"):
            keeps_in_fw1 = True
        if keeps_in_fw1:
            fw1_new.rules.append(deepcopy(r))

    fw1_hat.tables.append(fw1_new)

    # ─── Costruzione di ciascun fw2,i^ ────────────────────────────────
    for j in range(K):
        orig_fw2 = fw2_list[j]
        orig_fw2_tbl = orig_fw2.tables[0] if orig_fw2.tables else None
        fw2_policy = get_forward_policy(orig_fw2)
        move_accept, move_deny = decide_inheritance(fw1_policy, fw2_policy)
        upstream_iface = (fw2_upstream_ifaces[j] or "").strip() or None  # ★ da v5

        new_tbl = Table(star="*", table_name=orig_table.table_name)
        if orig_fw2_tbl is not None:
            new_tbl.chain_defs = deepcopy(orig_fw2_tbl.chain_defs)
        chain_name = f"{custom_chain_prefix}{j}"
        new_tbl.chain_defs.append(_make_custom_chain(chain_name))

        # ── Blocco A — catena custom REDIAL_A_<j> ─────────────────────
        for r in inherited[j]:
            if _is_nonterminating(r.action):
                new_r = deepcopy(r)
                new_r.chain = chain_name
                new_tbl.rules.append(new_r)
                continue
            if _is_allow(r.action):
                if not move_accept:
                    continue
                new_r = deepcopy(r)
                new_r.chain = chain_name
                new_r.action = "RETURN"
                new_r.action_params = {}
                new_tbl.rules.append(new_r)
                continue
            if _is_deny(r.action):
                if not move_deny:
                    continue
                new_r = deepcopy(r)
                new_r.chain = chain_name
                a = _norm(r.action)
                new_r.action = a if a in ("DROP", "REJECT") else "DROP"
                if new_r.action == "DROP":
                    new_r.action_params = {}
                new_tbl.rules.append(new_r)
                continue

        # ── Salto FORWARD → REDIAL_A_<j> ──────────────────────────────
        # ★ da v5: -i upstream_iface se fornita (topology-agnostic),
        #   altrimenti fallback al vecchio -s d0.
        if upstream_iface is not None:
            jump_rule = Rule(
                chain="FORWARD",
                src=None, dst=None,
                in_iface=upstream_iface,
                proto=None, sport=None, dport=None,
                icmp_type=None,
                action=chain_name,
            )
        else:
            jump_rule = Rule(
                chain="FORWARD",
                src=d0, dst=None,
                proto=None, sport=None, dport=None,
                icmp_type=None,
                action=chain_name,
            )
        new_tbl.rules.append(jump_rule)

        # ── Blocco B — regole originali di fw2,i, verbatim ────────────
        if orig_fw2_tbl is not None:
            for r in orig_fw2_tbl.rules:
                new_tbl.rules.append(deepcopy(r))

        fw2_hat[j].tables.append(new_tbl)

    return fw1_hat, fw2_hat


# ──────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    convert_rules_txt_to_xml(rules_txt="rules20250716.rules", rules_xml="rules.xml")
    fw1 = parse_iptables_xml_to_firewall("rules.xml")

    fw2_list = [
        parse_iptables_xml_to_firewall("fw2_1.xml"),
    ]

    d0 = ipaddress.IPv4Network("10.0.0.0/24", strict=False)
    d2_list = [ipaddress.IPv4Network("10.0.2.0/24", strict=False)]
    dn = [ipaddress.IPv4Network("10.0.1.0/24", strict=False)]

    fw1_hat, fw2_hat = redial(
        fw1, fw2_list, d2_list, d0, dn,
        log_strategy="move",
        fw2_upstream_ifaces=["veth-fw2-up"],   # uno per ogni fw2 in fw2_list
    )

    with open("iptables_fw1.rules", "w") as f:
        f.write(firewall_to_iptables_save(fw1_hat))
    for i, fw in enumerate(fw2_hat):
        with open(f"iptables_fw2_{i}.rules", "w") as f:
            f.write(firewall_to_iptables_save(fw))
