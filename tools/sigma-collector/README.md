# sigma-collector — `sigma_collector_subnet.py` (v2.1)

Measures **σ**, the average number of rules a packet traverses in the firewall, separately for net1 and net2. It reads the real iptables counters of the firewall (FW1), before and after REDIAL. It then computes the gain **Γ** and its theoretical bounds Γ_M / Γ_av / Γ_m, following the REDIAL paper (IEEE TIFS 2021, Sec. IV-A, eq. 3–12).

Runs on TS-P5 (via SSH to the firewall) or directly on the firewall (`--local`).

## Requirements

- Python 3, standard library only
- SSH key access from TS-P5 to the firewall, and passwordless `sudo` there for `ip netns exec FW iptables`
- Optional: the packet vectors `packets_net1.csv` / `packets_net2.csv` from `tools/gen-packets/`, to read the real wildcard fractions

## Usage

Three subcommands:

```bash
# 1. before EVERY run: reset the chain counters
./sigma_collector_subnet.py zero

# 2a. after a PRE-REDIAL run
./sigma_collector_subnet.py collect -o pre.json \
    --packets-net1 packets_net1.csv --packets-net2 packets_net2.csv

# 2b. after a POST-REDIAL run (REDIAL applied, counters reset again)
./sigma_collector_subnet.py collect --post -o post.json

# 3. compare: measured Γ vs theoretical bounds
./sigma_collector_subnet.py compare pre.json post.json
```

The campaign scripts (`tools/campaign/`) run this whole sequence automatically.

### Global options (go *before* the subcommand)

| Option | Default | Meaning |
| --- | --- | --- |
| `--host` | `192.168.100.103` | Firewall management IP (TS-P360 = FW1) |
| `--user` | current user | SSH user |
| `-i`, `--identity` | — | SSH private key |
| `--netns` | `FW` | Firewall network namespace |
| `--chain` | `FORWARD` | iptables chain |
| `--net1` | `10.0.1.0/24` | Subnet that is **not** redistributed (D_{K+1}^N) |
| `--net2` | `10.0.2.0/24` | Subnet redistributed by REDIAL (D_1^K) |
| `--no-sudo` | off | Do not prefix `sudo` |
| `--local` | off | Run iptables locally (when executed on the firewall itself) |

### Subcommand options

| Subcommand | Option | Meaning |
| --- | --- | --- |
| `collect` | `--post` | POST run: look for the net2 shortcut, compute `h`, handle the wildcard leak |
| `collect` | `--rho R` | Fraction of packets towards net2 set on the sender; if missing, it is measured from the counters |
| `collect` | `--packets-net1/2 FILE` | Vectors used to read the real wildcard fractions f1/f2 |
| `collect` | `-o FILE` | Save the result as JSON (needed by `compare`) |
| `compare` | `--rho R` | Force ρ (default: ρ measured in the PRE run) |

## How it works

**Counters.** It reads `iptables -L <chain> -nvx --line-numbers` inside the firewall namespace.

**Cost model (first match).**
- A packet that matches the terminating rule at position *p* costs *p* rules.
- A packet that falls to the default policy costs *N* (all rules).
- Non-terminating targets (LOG, NFLOG, MARK, …) are ignored.
- Unknown targets are treated as terminating, with a warning.

**Rule classification**, in this order:
1. Comment tag `[REDIAL:net1]`, `[REDIAL:net2]`, `[REDIAL:wildcard]` or `[REDIAL:final]`
2. Otherwise, the destination subnet (`subnet_of` net2 / net1)
3. Otherwise, the rule counts as **wildcard**

**Wildcard attribution.** Wildcard rules have one counter shared by both nets, so the script splits it:
- **PRE**: net2 gets a share of ρ, or ρ·f2 / ((1−ρ)·f1 + ρ·f2) when the vectors are given.
- **POST**: net2 gets 0. After REDIAL, wildcard packets towards net2 match the shortcut `-d 10.0.2.0/24 -j ACCEPT` and never reach the trailing wildcard rule (the "leak"). So the whole wildcard counter belongs to net1.

**h.** In POST, `h` is the position of the first `ACCEPT` rule whose destination is exactly net2 (the shortcut). The check `σ_net2 ≈ h` (|difference| < 1) confirms that REDIAL is active.

## Output

`collect` prints three sections:
1. σ per subnet, wildcards **excluded** (legit-only). Each value comes with "expected" = the mean position of that class's rules.
2. σ per subnet, wildcards **included**. These are the σ values defined in the paper.
3. σ_overall: all packets, policy included (exact).

With `-o`, the JSON also stores the packet counts, `rho_measured` / `rho_used`, `wildcard_share_net2`, `h`, all σ values and the number of rules per class.

`compare` prints three sections:
- **(A)** Paper Γ (eq. 5), computed on the wildcard-included σ, against Γ_M (eq. 10, inherited rules at the top), Γ_av (eq. 11, uniform) and Γ_m (eq. 12, inherited rules at the bottom). It says `[OK]` if Γ falls inside [Γ_m, Γ_M].
- **(B)** The same calculation legit-only, as a breakdown by rule class.
- **(C)** Measured total Γ = σ_1^N PRE / σ_1^N POST.

## Configuration

Defaults match the x86 testbed (FW1 = TS-P360 in namespace `FW`). For the Raspberry Pi 5, pass `--host 192.168.100.104`, and `--netns` / `--user` if they differ.

## Notes

- **Always run `zero` before each run.** iptables counters are cumulative, so skipping it mixes runs together.
- The counters only see packets that reached the firewall. Packets lost before it are not counted.
- `sigma_simulate.py`, an offline σ simulator mentioned in older notes and in `gen_packets_v2.py`, was not found on the testbed and is not included.

## History

- **v1.3** (`sigma_collector`): legit-only σ per subnet.
- **v2.0**: σ per subnet **including** wildcards; attribution of the shared wildcard counter (from ρ and, optionally, from the real fractions in the vectors); correct handling of the POST leak; sectioned output.
- **v2.1**: `compare` computes Γ and the bounds on the wildcard-included σ, as in the paper. ρ "paper" includes wildcard packets in the per-destination count. The legit-only version stays as section (B).
