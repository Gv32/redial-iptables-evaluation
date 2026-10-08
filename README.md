# redial-iptables-evaluation

Tools and testbed scripts for the experimental evaluation of **REDIAL** rule redistribution on Linux **iptables** firewalls (x86 and Raspberry Pi 5).

Master's thesis — *Experimental Evaluation of REDIAL: Latency, Hardware Portability, and DoS Resilience in Linux Firewalls* — Giovanni Drago, Politecnico di Torino, 2026.

REDIAL (Durante et al., IEEE TIFS 2021) moves the rules for some destination domains from an upstream firewall to a downstream one, so the upstream firewall evaluates fewer rules per packet. This repository contains everything used to measure that effect on a real testbed:

- σ: the average number of rules a packet traverses
- the gain Γ
- the forwarding delay and the loss

This repository contains **code only**. Captures (pcap), rulesets, measurement results and plot scripts are not included.

## Testbed

| Host | Mgmt IP | Role |
| --- | --- | --- |
| **TS-P5** | 192.168.100.101 | Traffic generator + capture. Namespaces `SX` (sender), `TAP` (mirror), `RX` (net1 sink), `DST` (net2 sink); Intel I350 NICs with hardware timestamps |
| **TS-P360** | 192.168.100.103 | Firewall under test (FW1, x86), iptables in namespace `FW` |
| **Raspberry Pi 5** | 192.168.100.104 | Firewall under test (ARM), or FW2 in the two-firewall setup |
| **ieiitp97** | 192.168.100.102 | REDIAL orchestrator (bastion); applies PRE/POST rulesets on the firewall over SSH |

| Domain | Subnet | Meaning |
| --- | --- | --- |
| d0 | 10.0.0.0/24 | Sources (sender `SX`, 10.0.0.1) |
| net1 / dn | 10.0.1.0/24 | Domain that stays on FW1 (sink `RX`, 10.0.1.3) |
| net2 / d2 | 10.0.2.0/24 | Domain redistributed by REDIAL (sink `DST`) |

## Repository map

| Folder | What it does | Runs on |
| --- | --- | --- |
| [`tools/gen-fw-rules`](tools/gen-fw-rules) | Generates the firewall rulesets (`gen_fw_rules_v6.py`) | any |
| [`tools/gen-packets`](tools/gen-packets) | Generates the packet vectors that match the ruleset (`gen_packets_v2.py`) | any |
| [`tools/namespace`](tools/namespaces) | Creates the namespaces and interfaces of the testbed | TS-P5 |
| [`tools/load-fw`](tools/load-fw) | Loads a ruleset on the firewall | TS-P5 |
| [`tools/sendpkts`](tools/sendpkts) | C traffic generator: replays the vectors with a net1/net2 split and a rate ramp | TS-P5 |
| [`tools/udpramp`](tools/udpramp) | C single-flow UDP generator with a rate ramp (probe for the h sweep) | TS-P5 |
| [`tools/capture`](tools/capture) | Hardware-timestamped capture on TAP / RX / DST (`listen-redial.sh`) | TS-P5 |
| [`tools/run-redial`](tools/run-redial) | One measurement run: capture + `sendpkts` | TS-P5 |
| [`tools/sigma-collector`](tools/sigma-collector) | σ per subnet from the iptables counters, plus Γ against the theoretical bounds | TS-P5 → FW |
| [`tools/compare-redial`](tools/compare-redial) | Offline analysis of the TAP/RX pcaps: Δ delay, loss, leaks; window statistics | any |
| [`tools/campaign`](tools/campaign) | Full PRE/POST campaign for one ruleset (3 values of ρ) | TS-P5 |
| [`tools/sweep-passall`](tools/sweep-passall) | "Pass-all at position h" sweep: delay as a function of σ = h | TS-P5 |
| [`redial`](redial) | REDIAL FW1-only (used for the thesis measurements) | ieiitp97 |
| [`redial/full`](redial/full) | Full two-firewall REDIAL (`redial_v5.py`) | ieiitp97 |

Each folder has its own `README.md` covering usage, options, configuration (hardcoded IPs, interfaces, cores, users) and version history.

## Typical workflow (one REDIAL campaign)

```bash
# 1. ruleset + matching packet vectors
python3 gen_fw_rules_v6.py -o fw1.rules ...                # see tools/gen-fw-rules
python3 gen_packets_v2.py -r fw1.rules --count 10000 --seed 42

# 2. load the PRE ruleset on the firewall
./load-fw.sh fw1.rules                                     # see tools/load-fw

# 3. campaign (TS-P5, all tools in one working folder, normal user)
./campagna-redial.sh --tag my-campaign --rules fw1.rules --offset -11764
#    -> 3 PRE runs, then it asks you to apply REDIAL on ieiitp97:
#       cd ~/redial-single-fw && unset WORKDIR && ./run-fw1-only.sh
#    -> 3 POST runs, σ/Γ comparison, summary.txt
```

What happens inside a single run:

```text
sigma_collector zero → run-redial.sh (listen-redial.sh + sendpkts) → sigma_collector collect → compare-redial.py
```

## Important notes

- **The scripts expect to be in one working folder.** They call each other with relative paths (`./run-redial.sh`, `./sendpkts`, …). On the testbed that folder is `~/Test-Sigma`; from this repo, copy the files of the `tools/*` folders you need into one directory.
- **RX clock offset:** always pass the current calibration (`--offset` / `--rx-offset-ns`). The defaults written in some scripts (`-11973`, `0`) are outdated; the last value used in the thesis is −11764 ns.
- **Passwords and keys are not in the repo.** The REDIAL scripts read the SSH/sudo password from an external file (`PASS_FILE`), which must never be committed.
- The code is kept **identical to the version used for the thesis**. Testbed-specific values are documented in each README instead of being moved to a config file.
