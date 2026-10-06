"""
redial_v5.py — REDIAL allineato a Durante et al., TIFS 2021, esteso al
match per interfaccia di ingresso sul salto fw2,i^.FORWARD → REDIAL_A_<j>.

Differenze rispetto a redial_v4.py (★ = punto di modifica):

  ★ AGGIUNTO    parametro `fw2_upstream_ifaces`: lista parallela a
                fw2_list. Ogni elemento è il nome dell'interfaccia
                (dentro la netns di fw2,j) attraverso cui arriva il
                traffico da fw1. Se None per un dato j, si torna al
                vecchio comportamento (match per -s d0).

  ★ MODIFICATO  la Rule che genera il salto fw2,i^.FORWARD → REDIAL_A_<j>
                ora preferisce `in_iface=<iface>` a `src=d0`. Questo
                elimina il gap di sicurezza quando sorgenti diverse da
                d0 (es. d_n) attraversano fw1: il match per interfaccia
                cattura *tutto* il traffico transitato da fw1, qualunque
                sia la sua source IP, mentre traffico intra-foglia
                (d2,j → d2,i, entra da un'altra iface) salta correttamente
                il blocco A.

  ★ INVARIATO   tutto il resto: shortcut su fw1^, gestione D^N_{K+1},
                trasformazioni ACCEPT→RETURN e DENY→DROP/REJECT,
                decide_inheritance() sui 4 casi di default policy,
                supporto target non-terminanti (LOG/MARK/...) con
                log_strategy.

Garanzie semantiche (estensione della v4):

  Pacchetto da d0 (passa per fw1, arriva su fw2 via veth-fw2-up):
    fw1^   → matcha shortcut -d d2,i → ACCEPT
    fw2,i^ → -i veth-fw2-up matcha → entra in REDIAL_A_<i> → stesso
             verdetto della v4 (DROP/REJECT diretto, oppure RETURN →
             blocco B).

  Pacchetto da dn (es. 10.0.1.0/24) che attraversa fw1 verso d2,i:
    fw1^   → matcha shortcut -d d2,i → ACCEPT (come prima)
    fw2,i^ → -i veth-fw2-up matcha lo stesso (perché arriva da fw1
             indipendentemente dalla source) → entra in REDIAL_A_<i> →
             stesso filtraggio che applicava fw1 originale. ✓ GAP FIX

  Pacchetto intra-foglia d2,j → d2,i (NON passa per fw1):
    fw2,i^ → entra da un'iface diversa (es. veth-fw2-d2j) → -i
             veth-fw2-up NON matcha → salta REDIAL_A_<i> → blocco B.
             Stesso comportamento del paper.
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
    f1 = _norm(fw1_policy)
    f2 = _norm(fw2_policy)
    if f1 == "DROP" and f2 == "ACCEPT":
        return (False, True)
    if f1 == "DROP" and f2 == "DROP":
        return (True, True)
    if f1 == "ACCEPT" and f2 == "DROP":
        return (True, True)
    if f1 == "ACCEPT" and f2 == "ACCEPT":
        return (False, True)
    return (True, True)


def _make_custom_chain(name: str) -> ChainDef:
    return ChainDef(
        colon=":",
        chain_id=name,
        ext_chain_policy="-",
        counters=Counters(packets=0, bytes=0),
    )


# ──────────────────────────────────────────────────────────────────────
# Algoritmo REDIAL — v5
# ──────────────────────────────────────────────────────────────────────

def redial(
    fw1: Firewall,
    fw2_list: List[Firewall],
    d2_list: List[ipaddress.IPv4Network],
    d0: ipaddress.IPv4Network,
    dn: List[ipaddress.IPv4Network],
    custom_chain_prefix: str = "REDIAL_A_",
    log_strategy: Literal["move", "keep", "duplicate"] = "move",
    fw2_upstream_ifaces: Optional[List[Optional[str]]] = None,        # ★ NEW
):
    """
    Applica REDIAL con codifica iptables fedele al paper, esteso al
    match per interfaccia sul salto REDIAL_A_<j>.

    Nuovo parametro rispetto a v4:
      fw2_upstream_ifaces : list parallela a fw2_list. Ogni elemento è
        il nome dell'interfaccia (es. "veth-fw2-up") da cui arriva su
        fw2,j il traffico che ha attraversato fw1. Se None per un dato
        j (o se l'intera lista è None), si torna al match -s d0.
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

    # ─── Costruzione di fw1^ + raccolta delle regole ereditate ─────────
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

    # ─── Costruzione di ciascun fw2,i^ ─────────────────────────────────
    for j in range(K):
        orig_fw2 = fw2_list[j]
        orig_fw2_tbl = orig_fw2.tables[0] if orig_fw2.tables else None
        fw2_policy = get_forward_policy(orig_fw2)
        move_accept, move_deny = decide_inheritance(fw1_policy, fw2_policy)
        upstream_iface = (fw2_upstream_ifaces[j] or "").strip() or None  # ★ NEW

        new_tbl = Table(star="*", table_name=orig_table.table_name)
        if orig_fw2_tbl is not None:
            new_tbl.chain_defs = deepcopy(orig_fw2_tbl.chain_defs)
        chain_name = f"{custom_chain_prefix}{j}"
        new_tbl.chain_defs.append(_make_custom_chain(chain_name))

        # ── Blocco A — catena custom REDIAL_A_<j> ──────────────────────
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

        # ── Salto FORWARD → REDIAL_A_<j> ─────────────────────────────
        # ★ FIX: usa -i upstream_iface se fornita (topology-agnostic),
        # altrimenti fallback al vecchio -s d0.
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

        # ── Blocco B — regole originali di fw2,i, verbatim ───────────
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

    # ★ Topology-agnostic: passa il nome dell'interfaccia di fw2 verso fw1.
    # Se non sai ancora il nome, lascia None: si torna al vecchio comportamento.
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
