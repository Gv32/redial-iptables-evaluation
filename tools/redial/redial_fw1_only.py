#!/usr/bin/env python3
"""
redial_fw1_only.py

Emulazione FW1-only del post-REDIAL.

Scopo:
    misurare quanto FW1 si alleggerisce quando REDIAL sposta altrove
    le regole relative a d2.

Importante:
    - Il comportamento su FW1 deve essere identico al REDIAL completo.
    - FW2 viene ignorato.
    - Non viene generato fw2.new.rules.
    - Non viene applicata nessuna catena REDIAL_A_0 su FW2.

Output:
    fw1_hat = FW1^ alleggerito
"""

import argparse
import ipaddress
from copy import deepcopy
from typing import List, Literal, Optional

from RedialUtils import (
    Firewall,
    Table,
    Rule,
    parse_iptables_xml_to_firewall,
    firewall_to_iptables_save,
)


_NON_TERMINATING = {
    "LOG", "NFLOG", "AUDIT", "MARK", "CONNMARK", "TRACE", "TEE", "CT",
}


def _norm(action: Optional[str]) -> str:
    return (action or "").strip().upper()


def _is_nonterminating(action: Optional[str]) -> bool:
    return _norm(action) in _NON_TERMINATING


def _touches_network(rule: Rule, net: ipaddress.IPv4Network) -> bool:
    """
    True se la regola può matchare pacchetti verso net.

    Se dst è None, la regola è wildcard sulla destinazione:
    quindi interseca qualunque dominio.
    """
    return rule.dst is None or rule.dst.overlaps(net)


def _touches_any(rule: Rule, nets: List[ipaddress.IPv4Network]) -> bool:
    if rule.dst is None:
        return True
    return any(rule.dst.overlaps(n) for n in nets)


def redial_fw1_only(
    fw1: Firewall,
    d2_list: List[ipaddress.IPv4Network],
    dn: List[ipaddress.IPv4Network],
    log_strategy: Literal["move", "keep", "duplicate"] = "move",
) -> Firewall:
    """
    Costruisce solo FW1^, esattamente come farebbe REDIAL completo.

    Parametri:
        fw1:
            firewall upstream originale.
        d2_list:
            domini ridistribuiti verso firewall downstream.
            Nel banco attuale normalmente contiene solo 10.0.2.0/24.
        dn:
            domini non ridistribuiti, che restano filtrati da FW1.
            Nel banco attuale normalmente contiene 10.0.1.0/24.
        log_strategy:
            stessa semantica della versione completa:
                move      → target non terminanti vengono spostati se toccano d2
                keep      → target non terminanti restano su FW1
                duplicate → target non terminanti restano su FW1 e verrebbero anche copiati a valle
            In questa versione FW2 è ignorato, quindi duplicate equivale a keep
            dal punto di vista dell'output finale su FW1.

    Ritorna:
        fw1_hat:
            firewall upstream alleggerito.
    """
    assert log_strategy in ("move", "keep", "duplicate")

    fw1_hat = Firewall()

    if not fw1.tables:
        return fw1_hat

    orig_table = fw1.tables[0]

    fw1_new = Table(star="*", table_name=orig_table.table_name)
    fw1_new.chain_defs = deepcopy(orig_table.chain_defs)

    shortcut_inserted = False

    for rule in orig_table.rules:
        is_nonterm = _is_nonterminating(rule.action)

        # Nel REDIAL completo, questa condizione decide se la regola
        # deve essere considerata per la migrazione verso un downstream FW.
        touches_d2 = any(_touches_network(rule, d2) for d2 in d2_list)

        # Appena REDIAL incontra la prima regola che tocca d2,
        # inserisce su FW1^ la shortcut verso i domini ridistribuiti.
        if touches_d2 and not shortcut_inserted:
            shortcut_inserted = True

            for d2 in d2_list:
                fw1_new.rules.append(Rule(
                    chain="FORWARD",
                    src=None,
                    dst=d2,
                    proto=None,
                    sport=None,
                    dport=None,
                    icmp_type=None,
                    action="ACCEPT",
                ))

        # Nel REDIAL completo:
        # - se una regola tocca d2, verrebbe copiata nel blocco di FW2;
        # - se tocca dn, deve restare su FW1.
        #
        # In questa versione FW2 è bypassato, quindi l'unica domanda è:
        # "questa regola serve ancora a FW1 per traffico non ridistribuito?"
        keep_on_fw1 = _touches_any(rule, dn)

        # Target non terminanti: preserva la stessa politica della versione completa.
        if is_nonterm and log_strategy in ("keep", "duplicate"):
            keep_on_fw1 = True

        if keep_on_fw1:
            fw1_new.rules.append(deepcopy(rule))

        # Se la regola tocca solo d2 e non dn:
        # - nel REDIAL completo verrebbe gestita da FW2;
        # - qui viene semplicemente rimossa da FW1^.
        #
        # Questo è esattamente l'effetto che vogliamo misurare su FW1:
        # le regole migrate non pesano più sul firewall upstream.

    fw1_hat.tables.append(fw1_new)
    return fw1_hat


def parse_net(value: str) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network(value, strict=False)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Genera solo FW1^, ignorando FW2, per misure FW1-only post-REDIAL."
    )

    ap.add_argument("--fw1-xml", required=True)

    ap.add_argument(
        "--d2",
        action="append",
        required=True,
        type=parse_net,
        help="Dominio ridistribuito verso FW2. Ripetibile.",
    )

    ap.add_argument(
        "--dn",
        action="append",
        required=True,
        type=parse_net,
        help="Dominio non ridistribuito, che resta filtrato da FW1. Ripetibile.",
    )

    ap.add_argument(
        "--log-strategy",
        default="move",
        choices=("move", "keep", "duplicate"),
    )

    ap.add_argument("--out-fw1", required=True)

    args = ap.parse_args()

    fw1 = parse_iptables_xml_to_firewall(args.fw1_xml)

    fw1_hat = redial_fw1_only(
        fw1=fw1,
        d2_list=args.d2,
        dn=args.dn,
        log_strategy=args.log_strategy,
    )

    with open(args.out_fw1, "w") as f:
        f.write(firewall_to_iptables_save(fw1_hat))

    print(f"[OK] FW1^ generated -> {args.out_fw1}")
    print("[INFO] FW2 ignored by design")


if __name__ == "__main__":
    main()
