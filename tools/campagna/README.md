# campaign — `campagna-redial.sh`

Runs a full REDIAL campaign for **one ruleset** loaded on the firewall:

- **3 PRE runs**, one per ρ = 0.25 / 0.5 / 0.75 (share of traffic towards net2)
- **pause** while you apply REDIAL from the orchestrator
- **3 POST runs**, one per ρ
- σ comparison and a summary of the forwarding times

This is the script used for the thesis campaigns. It chains the other tools:

```text
sigma_collector_subnet.py zero → run-redial.sh → capture checks → sigma_collector_subnet.py collect → compare-redial.py
```

## Requirements

- All the tools in **one working folder**. The script calls them with relative paths: `./run-redial.sh`, `./listen-redial.sh`, `./sendpkts`, `sigma_collector_subnet.py`, `./compare-redial.py`. On the testbed this folder is `~/Test-Sigma`; from this repo, copy the files from the `tools/*/` folders into one directory.
- The **PRE ruleset loaded on the firewall** (`tools/load-fw/`). The same file must be in the working folder (`--rules`).
- The packet vectors, regenerated for that ruleset:
  ```bash
  python3 gen_packets_v2.py -r <rules> --count 10000 --seed 42
  ```
- SSH key access to the firewall (for the collector), `sudo` on TS-P5, and the REDIAL orchestrator on ieiitp97 (`~/redial-single-fw`)
- At least **25 GB free**: about 3.4 GB of pcaps per run, 6 runs

## Usage

```bash
chmod +x campagna-redial.sh
./campagna-redial.sh --tag <name> [--rate 400000] [--rules fw1.rules] \
    [--pre-rules 601] [--post-rules N] --offset -11764
```

**Run it as a normal user, never with `sudo`.** It uses `sudo` internally only where needed. Run as root, the collector would SSH as `root@FW`.

| Option | Default | Meaning |
| --- | --- | --- |
| `--tag` | — (required) | Campaign name; output goes to `campagne/<tag>/` |
| `--rate` | `400000` | Total pps. Each run is a single 60 s step (`--ramp 60:<rate>`). |
| `--rules` | `fw1.rules` | Ruleset loaded on the firewall (gives the expected DENY to `compare-redial.py`) |
| `--pre-rules` | `601` | Expected number of rules on the firewall in PRE. The script stops if it differs. |
| `--post-rules` | *(empty)* | Expected number of rules in POST (optional check) |
| `--offset` | `-11973` | RX clock offset in ns. **The default is outdated: always pass the current calibration (−11764 ns in the thesis).** |

## What each run does

1. **Zero and check.** Resets the firewall counters and checks the rule count (PRE/POST state).
2. **Measure.** Runs `sudo ./run-redial.sh --split <s> --cpu 2 --ramp 60:<rate>`. The split is 75,25 / 50,50 / 25,75 (net1,net2) for ρ = 0.25 / 0.5 / 0.75.
3. **Capture check.** The TAP and RX packet counts must be equal. If they differ, the run's files are deleted and the run is repeated (up to 3 attempts; then the script stops, because repeated losses mean a testbed or ring-buffer problem).
4. **Store.** Moves the pcaps and the epoch file into `campagne/<tag>/rho<r>/{pre,post}/`.
5. **σ.** Runs `sigma_collector_subnet.py collect` (POST adds `--post --rho <r>`) → `sigma_{pre,post}.json`.
6. **Knee check.** If rate × σ_overall exceeds about **130 M rule evaluations/s**, the firewall is past its knee: the times at that rate are not reliable (the σ values stay valid).
7. **Δ.** Runs `compare-redial.py` → `delta.csv` / `delta.txt`.
8. **Std check.** Checks the std of the `tot` row: at most **40 µs PRE / 20 µs POST**; otherwise the times should be discarded or repeated.

Between PRE and POST the script stops and asks you to apply REDIAL on ieiitp97:

```bash
cd ~/redial-single-fw && unset WORKDIR && ./run-fw1-only.sh
```

Press Enter when the firewall is in POST state.

At the end, for each ρ it runs `sigma_collector_subnet.py compare` → `compare_sigma.txt`. Then it writes `summary.txt` with:
- D_pre, D_post and their difference (µs, from the `tot` rows)
- a cross-check rebuilt from the per-net values of the 50/50 run alone

## Output

```text
campagne/<tag>/
├── summary.txt
└── rho025/ rho05/ rho075/
    ├── compare_sigma.txt
    ├── pre/   tap_*.pcap rx_*.pcap ramp_start_*.epoch run.log sigma_pre.json  delta.csv delta.txt
    └── post/  tap_*.pcap rx_*.pcap ramp_start_*.epoch run.log sigma_post.json delta.csv delta.txt
```

A campaign takes about 20 minutes plus the REDIAL pause, and about 20 GB.

**Rollback** to PRE (on ieiitp97):

```bash
export WORKDIR=<run dir> && ./start.sh pre    # or ./start.sh pre-last
```

## Configuration

| Value in the script | Meaning |
| --- | --- |
| `--cpu 2` | Core used for `sendpkts` in the campaigns |
| `STD_PRE=40`, `STD_POST=20` | Std limits in µs |
| `KNEE_M=130` | Knee of the x86 firewall, in M evaluations/s |
| `MAX_RETRY=3` | Attempts per run when capture loses packets |
| `RHOS="0.25 0.5 0.75"` | ρ values |

**Raspberry Pi 5.** `campagna-redial-pi.sh` (not included) was identical except for `--host 192.168.100.104` on the two `sigma_collector_subnet.py` calls (`zero` and `collect`). To run on the Pi, add that option to those two lines.

## Notes

- The capture check (TAP count = RX count) assumes that **all traffic is accepted**, as in the thesis rulesets (wildcards in ACCEPT, no firewall loss at the campaign rate). With DROP rules or firewall loss, every run would look incomplete and be retried.
- The script reminds you before starting: silence periodic timers, and run only during the day.
