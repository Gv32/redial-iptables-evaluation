"""
redialUtils.py — v4.2 (drop-in replacement della v4.1).

Differenze rispetto a v4.1 (★ = punto di modifica):
  ★ FIX 8  Aggiunto campo `in_iface: Optional[str] = None` alla dataclass
           Rule. Permette di emettere `-i <iface>` su una regola, usato
           dal fix topology-agnostic in redial_v5.py: il salto verso
           REDIAL_A_<j> matcha per interfaccia di ingresso invece che
           per source IP, eliminando il gap quando sorgenti diverse da
           d0 attraversano fw1.
  ★ FIX 9  Il serializer emette `-i <iface>` subito dopo -s/-d (ordine
           canonico di iptables-save). Skippa se in_iface è None/vuoto.
           Parser invariato: in_iface non viene letto dall'XML, viene
           solo SCRITTO da redial() quando costruisce la jump.

USO: drop-in replacement di RedialUtils.py. Redial.py va aggiornato a v5
per sfruttare il nuovo campo.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import ipaddress
import xml.etree.ElementTree as ET
import os
import subprocess
from datetime import datetime


# ── Dataclasses ───────────────────────────────────────────────────────

@dataclass
class Counters:
    packets: int
    bytes: int


@dataclass
class ChainDef:
    colon: str
    chain_id: str
    ext_chain_policy: str
    counters: Optional[Counters]


@dataclass
class Rule:
    chain: str
    src: Optional[ipaddress.IPv4Network] = None
    dst: Optional[ipaddress.IPv4Network] = None
    proto: Optional[str] = None
    sport: Optional[str] = None
    dport: Optional[str] = None
    icmp_type: Optional[str] = None
    action: Optional[str] = None
    src_negate: bool = False
    in_iface: Optional[str] = None                                  # ★ FIX 8
    action_params: Dict[str, str] = field(default_factory=dict)
    extra_matches: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class Table:
    star: str
    table_name: str
    chain_defs: List[ChainDef] = field(default_factory=list)
    rules: List[Rule] = field(default_factory=list)
    commit_string: str = "COMMIT"


@dataclass
class Firewall:
    tables: List[Table] = field(default_factory=list)


# ── Helpers ───────────────────────────────────────────────────────────

_BASIC_COND_TAGS = {"match", "tcp", "udp", "icmp"}


def _parse_port_spec(text: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    t = text.strip()
    if not t:
        return None
    if ":" in t:
        a, _, b = t.partition(":")
        try:
            ia, ib = int(a), int(b)
            if 0 <= ia <= 65535 and 0 <= ib <= 65535 and ia <= ib:
                return f"{ia}:{ib}"
        except ValueError:
            pass
        print(f"[!] Invalid port range: {text}")
        return None
    try:
        n = int(t)
        if 0 <= n <= 65535:
            return str(n)
        print(f"[!] Port out of range: {text}")
        return None
    except ValueError:
        return t


def _strip_outer_quotes(text: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'"):
        return text[1:-1]
    return text


def _emit_param_value(parts: List[str], flag: str, value: Optional[str]) -> None:
    if value is None:
        return
    v = str(value)
    if v == "":
        return
    if any(c in v for c in (" ", "\t")):
        parts.append(f'{flag} "{v}"')
    else:
        parts.append(f"{flag} {v}")


# ── I/O ───────────────────────────────────────────────────────────────

def convert_rules_txt_to_xml(rules_txt="00_gdm.test", rules_xml="rules.xml"):
    if not os.path.exists(rules_txt):
        raise FileNotFoundError(f"'{rules_txt}' not found. Please export with iptables-save.")
    try:
        with open(rules_txt, "rb") as infile, open(rules_xml, "wb") as outfile:
            subprocess.run(["iptables-xml"], stdin=infile, stdout=outfile, check=True)
    except FileNotFoundError:
        raise RuntimeError("iptables-xml not found. Install with `apt install iptables-dev`.")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"iptables-xml failed: {e}")


# ── Parser ────────────────────────────────────────────────────────────

def parse_iptables_xml_to_firewall(xml_file_path: str) -> Firewall:
    with open(xml_file_path, "r") as f:
        xml_content = f.read()
    root = ET.fromstring(xml_content)
    tables: List[Table] = []

    for table_elem in root.findall("table"):
        table_name = table_elem.get("name") or "filter"
        chain_defs: List[ChainDef] = []
        rules: List[Rule] = []

        for chain_elem in table_elem.findall("chain"):
            chain_name = chain_elem.get("name", "")
            policy = chain_elem.get("policy", "") or ""
            pkts = chain_elem.get("packet-count", "0")
            bytes_ = chain_elem.get("byte-count", "0")
            counters = Counters(packets=int(pkts), bytes=int(bytes_))
            chain_defs.append(ChainDef(":", chain_name, policy, counters))

            for rule_elem in chain_elem.findall("rule"):
                rule = Rule(chain=chain_name)

                conditions = rule_elem.find("conditions")
                if conditions is not None:
                    m = conditions.find("match")
                    if m is not None:
                        s, d, p = m.find("s"), m.find("d"), m.find("p")
                        if s is not None and s.text:
                            try:
                                rule.src = ipaddress.ip_network(s.text.strip(), strict=False)
                            except ValueError:
                                print(f"[!] Invalid source IP: {s.text}")
                        if d is not None and d.text:
                            try:
                                rule.dst = ipaddress.ip_network(d.text.strip(), strict=False)
                            except ValueError:
                                print(f"[!] Invalid destination IP: {d.text}")
                        if p is not None and p.text:
                            rule.proto = p.text.strip().lower()

                    for proto_tag in ("tcp", "udp", "icmp"):
                        pe = conditions.find(proto_tag)
                        if pe is None:
                            continue
                        if proto_tag in ("tcp", "udp"):
                            sp = pe.find("sport")
                            dp = pe.find("dport")
                            if sp is not None:
                                rule.sport = _parse_port_spec(sp.text)
                            if dp is not None:
                                rule.dport = _parse_port_spec(dp.text)
                        else:
                            it = pe.find("icmp-type")
                            if it is not None and it.text:
                                rule.icmp_type = it.text.strip()
                        rule.proto = proto_tag

                    for child in conditions:
                        if child.tag in _BASIC_COND_TAGS:
                            continue
                        params: Dict[str, str] = {}
                        for sub in child:
                            if sub.text is None:
                                continue
                            val = _strip_outer_quotes(sub.text)
                            if val is None or val == "":
                                continue
                            params[sub.tag] = val
                        rule.extra_matches.append({"name": child.tag, "params": params})

                actions = rule_elem.find("actions")
                if actions is not None and len(actions):
                    action_elem = actions[0]
                    target = (action_elem.tag or "").strip()
                    if not target:
                        continue
                    rule.action = target
                    for child in action_elem:
                        if child.text is None:
                            continue
                        val = _strip_outer_quotes(child.text)
                        if val is None or val == "":
                            continue
                        rule.action_params[child.tag] = val

                rules.append(rule)

        tables.append(Table(star="*", table_name=table_name,
                            chain_defs=chain_defs, rules=rules))
    return Firewall(tables=tables)


# ── Serializer ────────────────────────────────────────────────────────

def firewall_to_iptables_save(firewall: Firewall) -> str:
    if firewall is None:
        raise TypeError("firewall_to_iptables_save: firewall is None")

    filter_table: Optional[Table] = None
    for table in firewall.tables:
        if table.table_name == "filter":
            filter_table = table
            break
    if filter_table is None:
        filter_table = Table(star="*", table_name="filter")
        firewall.tables.append(filter_table)

    existing = {c.chain_id for c in filter_table.chain_defs}
    for cname, cpol in (("INPUT", "ACCEPT"), ("OUTPUT", "ACCEPT"), ("FORWARD", "DROP")):
        if cname not in existing:
            filter_table.chain_defs.append(ChainDef(
                ":", cname, cpol, Counters(packets=0, bytes=0)
            ))

    lines: List[str] = []
    lines.append(f"# Generated by Redial (v4.2) on {datetime.now():%Y-%m-%d %H:%M:%S}")

    for table in firewall.tables:
        if not (table.table_name or "").strip():
            raise ValueError("Refusing to emit table with empty name")
        lines.append(f"*{table.table_name}")

        for chain in table.chain_defs:
            cid = (chain.chain_id or "").strip()
            if not cid:
                raise ValueError("Refusing to emit chain with empty name")
            pol = (chain.ext_chain_policy or "").strip() or "-"
            cnt = chain.counters
            pkts = cnt.packets if cnt else 0
            byts = cnt.bytes if cnt else 0
            lines.append(f":{cid} {pol} [{pkts}:{byts}]")

        for rule in table.rules:
            chain = (rule.chain or "").strip()
            if not chain:
                raise ValueError(f"Rule with empty chain: {rule}")
            parts: List[str] = [f"-A {chain}"]

            if rule.src:
                prefix = "! -s" if getattr(rule, "src_negate", False) else "-s"
                parts.append(f"{prefix} {rule.src}")
            if rule.dst:
                parts.append(f"-d {rule.dst}")

            # ★ FIX 9: emit -i <iface> subito dopo -s/-d (ordine canonico)
            in_iface = (getattr(rule, "in_iface", None) or "").strip()
            if in_iface:
                parts.append(f"-i {in_iface}")

            if rule.proto:
                parts.append(f"-p {rule.proto}")
                if rule.proto in ("tcp", "udp"):
                    if rule.sport is not None:
                        parts.append(f"--sport {rule.sport}")
                    if rule.dport is not None:
                        parts.append(f"--dport {rule.dport}")
                elif rule.proto == "icmp" and rule.icmp_type is not None:
                    parts.append(f"--icmp-type {rule.icmp_type}")

            for em in getattr(rule, "extra_matches", []) or []:
                name = (em.get("name") or "").strip()
                if not name:
                    continue
                parts.append(f"-m {name}")
                for k, v in (em.get("params") or {}).items():
                    _emit_param_value(parts, f"--{k}", v)

            if rule.action:
                tgt = rule.action.strip()
                if not tgt:
                    raise ValueError(f"Rule with empty action: {rule}")
                parts.append(f"-j {tgt}")
                for k, v in (getattr(rule, "action_params", {}) or {}).items():
                    _emit_param_value(parts, f"--{k}", v)

            lines.append(" ".join(parts))

        lines.append("COMMIT")
        lines.append("")

    out = "\n".join(lines)
    if not isinstance(out, str) or out.strip() == "":
        raise RuntimeError("firewall_to_iptables_save produced empty/None output")
    return out


def printFwObj(fw: Firewall) -> None:
    for table in fw.tables:
        print(f"\nTable: *{table.table_name}")
        for rule in table.rules:
            details = f"Chain {rule.chain} | {rule.proto} {rule.src} → {rule.dst}"
            if rule.in_iface:
                details += f" | -i {rule.in_iface}"
            if rule.proto in ("tcp", "udp"):
                pinfo = []
                if rule.sport is not None: pinfo.append(f"sport={rule.sport}")
                if rule.dport is not None: pinfo.append(f"dport={rule.dport}")
                if pinfo: details += " | " + " ".join(pinfo)
            elif rule.proto == "icmp" and rule.icmp_type is not None:
                details += f" | icmp-type={rule.icmp_type}"
            if rule.extra_matches:
                details += " | extra=" + ",".join(em["name"] for em in rule.extra_matches)
            details += f" | action={rule.action}"
            print("  " + details)


def set_default_drop_forward(firewall: Firewall) -> Firewall:
    for table in firewall.tables:
        if table.table_name == "filter":
            for cd in table.chain_defs:
                if cd.chain_id == "FORWARD":
                    cd.ext_chain_policy = "DROP"
                    return firewall
            table.chain_defs.append(ChainDef(
                ":", "FORWARD", "DROP", Counters(packets=0, bytes=0)
            ))
            return firewall
    t = Table(star="*", table_name="filter")
    t.chain_defs.append(ChainDef(
        ":", "FORWARD", "DROP", Counters(packets=0, bytes=0)
    ))
    firewall.tables.append(t)
    return firewall
