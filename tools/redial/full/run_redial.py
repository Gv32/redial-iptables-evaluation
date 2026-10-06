#!/usr/bin/env python3
import argparse, ipaddress
from redialUtils import parse_iptables_xml_to_firewall, firewall_to_iptables_save
from redial_v5 import redial

ap = argparse.ArgumentParser()
ap.add_argument("--fw1-xml", required=True)
ap.add_argument("--fw2-xml", required=True)
ap.add_argument("--d0",  default="10.0.0.0/24")
ap.add_argument("--d2",  default="10.0.2.0/24")
ap.add_argument("--dn",  default="10.0.1.0/24")
ap.add_argument(
    "--fw2-iface",
    action="append",
    default=[],
    help="Nome dell'interfaccia di fw2 (dentro la sua netns) verso fw1. "
         "Ripetibile: uno per ogni --fw2-xml, nello stesso ordine. "
         "Se omesso, redial() torna al match -s d0 (comportamento v4).",
)
ap.add_argument("--out-fw1", required=True)
ap.add_argument("--out-fw2", required=True)
args = ap.parse_args()

fw1 = parse_iptables_xml_to_firewall(args.fw1_xml)
fw2 = parse_iptables_xml_to_firewall(args.fw2_xml)
d0 = ipaddress.IPv4Network(args.d0, strict=False)
d2_list = [ipaddress.IPv4Network(args.d2, strict=False)]
dn = [ipaddress.IPv4Network(args.dn, strict=False)]

# Se l'utente non passa --fw2-iface, lasciamo None così redial() usa -s d0.
fw2_upstream_ifaces = args.fw2_iface if args.fw2_iface else None

fw1_hat, fw2_hat_list = redial(
    fw1, [fw2], d2_list, d0, dn,
    fw2_upstream_ifaces=fw2_upstream_ifaces,
)

with open(args.out_fw1, "w") as f:
    f.write(firewall_to_iptables_save(fw1_hat))
with open(args.out_fw2, "w") as f:
    f.write(firewall_to_iptables_save(fw2_hat_list[0]))

print(f"[run_redial] FW1 -> {args.out_fw1}")
print(f"[run_redial] FW2 -> {args.out_fw2}")
if fw2_upstream_ifaces:
    print(f"[run_redial] fw2 upstream ifaces: {fw2_upstream_ifaces}")
else:
    print("[run_redial] fw2 upstream ifaces: <none> (fallback a -s d0)")
