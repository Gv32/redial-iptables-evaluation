# gen-fw-rules — FW1 ruleset generator

`gen_fw_rules_v6.py` generates the FW1 ruleset used in all REDIAL experiments, in
`iptables-restore` format. It writes UDP ACCEPT rules towards two destination subnets
(net1 and net2), taken from a catalogue of 45 realistic UDP services (ICS/OT, IT
infrastructure, monitoring, storage). It then adds wildcard `/22` rules on known-insecure
ports and a final default-drop LOG rule. The chain policy is `FORWARD DROP`.
The rules are **shadow-free by construction**: every service has a unique port.

- **Runs on:** any machine with Python 3 (standard library only, no dependencies).
- **Output used by:** `load-fw.sh` (loads it on the FW), `gen_packets_v2.py` (packet vectors),
  `sigma_collector_subnet.py` (σ from the iptables counters).

## Testbed model

| Item | Value |
| --- | --- |
| Source of all traffic | `10.0.0.0/24` (every ACCEPT has `-s 10.0.0.0/24`) |
| net1 (filtered only by FW1, measured at RX) | `10.0.1.0/24` |
| net2 (offload subnet, moved by REDIAL to FW2) | `10.0.2.0/24` |
| Protocol | UDP only |
| Reserved host octets (never a destination) | `.0`, `.1` FW1.out, `.2` FW2.in, `.3` RX sink, `.255` |
| Wildcard rules | destination `10.0.0.0/22` (covers both nets), ports disjoint from the catalogue |

Each rule carries a comment `R#### [REDIAL:<tag>] <description>` with tag `net1`, `net2`,
`wildcard` or `final`. **Do not edit these tags:** the downstream tools depend on them.

## Usage

```bash
python3 gen_fw_rules_v6.py [options] -o <file.rules>
```

| Option | Default | Meaning |
| --- | --- | --- |
| `-o, --output` | `-` (stdout) | output file |
| `--limit N` | 1000 | total number of rules (with `--net-ratio`: exact total) |
| `--net-ratio R1,R2` | — | net1/net2 percentage of the ACCEPT rules, e.g. `25,75` |
| `--net-split N1,N2` | — | exact number of ACCEPT rules per net (mutually exclusive with `--net-ratio`) |
| `--order` | `grouped` | `n2n1`, `n1n2`, `mixed`, `grouped`, `random` (see below) |
| `--wildcard-rules N` | 48 | number of wildcard rules |
| `--wildcard-style` | `pairs` | `pairs` = LOG + action per port; `drop` = action only |
| `--wildcard-action` | `deny` | `deny` (DROP) or `accept` (ACCEPT) |
| `--wildcard-pos` | `tail` | `tail`, `head`, `mixed` (the final LOG always stays last) |
| `--no-final-log` | off | omit the final `FW-DROP-DEF` LOG rule (total −1) |
| `--seed N` | 42 | seed for destination hosts (and for `random` / wildcard `mixed`) |
| `--variants N` | auto | force the number of /32 hosts per service |

### Order and position h

h = position of the first net2 (relocatable) rule inside FW1.

| `--order` | Layout | h |
| --- | --- | --- |
| `n2n1` | all net2, then all net1 | **head** (h = 1) |
| `n1n2` | all net1, then all net2 | **tail** (h = \|net1\| + 1) |
| `mixed` | proportional interleaving \|net1\|:\|net2\| (no RNG, first rule always net1) | h = 2 |
| `grouped` | per service: net1 then net2 | — |
| `random` | reproducible shuffle driven by `--seed` | — |

The **center** position is obtained by generating with `--order n1n2` and moving the
`[REDIAL:net2]` block by hand.

## Rule counts

With `--net-ratio`: `ACCEPT = limit − wildcard − final`, split as `round(ACCEPT·R1/(R1+R2))`.
After REDIAL (FW1-only emulation) FW1 keeps the net1 rules, the wildcards, the final LOG
and **one shortcut rule** `-d 10.0.2.0/24 -j ACCEPT`.

| Split | net-split | PRE rules | POST rules |
| --- | --- | --- | --- |
| 50-50 | 275, 275 | 601 | 327 |
| 25-75 | 138, 412 | 601 | 190 |
| 75-25 | 412, 138 | 601 | 464 |

## Example (thesis matrix, h = head)

```bash
python3 gen_fw_rules_v6.py --seed 42 --order n2n1 --limit 601 --net-ratio 25,75 \
    --wildcard-rules 50 --wildcard-style pairs --wildcard-action accept \
    -o fw12575.rules
# then regenerate the packet vectors for this ruleset:
python3 gen_packets_v2.py -r fw12575.rules --count 10000 --seed 42
```

## Known pitfalls

- **Always regenerate the packet vectors** (`gen_packets_v2.py`) after changing the ruleset.
- With `--no-final-log` the totals drop by 1 (601 → 600): update `--pre-rules`/`--post-rules`
  in the campaign scripts and the expected count in `load-fw.sh`.
- Wildcard ports available: 50. With `pairs` each port uses 2 rules (so `--wildcard-rules 50`
  = 25 ports). An odd value with `pairs` is rounded down.
- If the warning "candidati insufficienti" appears, raise `--variants`.
- The first header line contains the generation timestamp: when comparing two rulesets,
  ignore lines starting with `#`.
- Source comments and messages are in Italian.

## Version history

| Version | Change |
| --- | --- |
| v4 | base generator (wildcards always DROP) |
| v5 | `--wildcard-action {deny,accept}` |
| v6 | `--order mixed` proportional to \|net1\|:\|net2\| (v5 alternated 1:1); `--no-final-log`; header shows the effective net-split |

Only v6 is published. With every order except `mixed` on asymmetric splits, v6 generates the
same rules as v5.
