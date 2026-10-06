# sweep-passall — `sweep-passall.sh` (v3) + `gen_sweep_rules.py`

"Pass-all" test, also called the h sweep. It measures how the forwarding delay grows with **σ**, the number of rules a packet traverses.

- Every ruleset has exactly **1001 rules**: 1000 filler rules that never match, plus **one pass-all rule at position h**.
- The probe stream (`udpramp`, one fixed 5-tuple) matches only the pass-all rule, so **σ = h exactly**.
- The script sweeps h, the rate and the replicas, with one independent run per combination.

## Files

| File | Role |
| --- | --- |
| `gen_sweep_rules.py` | Generates `rules_sweep/sweep_hNNNN.rules`, one file per h |
| `sweep-passall.sh` | For each ruleset: load it on the firewall, then run capture + `udpramp` + checks + `compare-redial.py` for every rep and rate |
| `listen.sh` | Capture used by the sweep: TAP + RX, filter `port <PORT>` (5000). It is the original `udpramp` listener, unchanged; `tools/capture/listen-redial.sh` is its successor for `sendpkts`. |

## 1. Generate the rulesets

```bash
# filler base: 500 net1 + 500 net2 ACCEPT rules, no wildcards
python3 gen_fw_rules_v6.py -o base_sweep.rules --seed 42 \
    --net-split 500,500 --wildcard-rules 0 --order n1n2
# one ruleset per h = 1, 51, 101, ..., 1001
python3 gen_sweep_rules.py -r base_sweep.rules --positions 1:1001:50 -d rules_sweep/
```

The docstring of `gen_sweep_rules.py` refers to `gen_fw_rules_v5.py`. The thesis used v5; v6 (`tools/gen-fw-rules/`) is the maintained version.

| Option | Default | Meaning |
| --- | --- | --- |
| `-r`, `--rules` | — (required) | Base ruleset the filler rules come from |
| `-d`, `--outdir` | `rules_sweep` | Output folder |
| `--filler` | `1000` | Number of filler rules |
| `--positions` | `1:1001:50` | `start:stop:step` for h (`stop` is always included) |

What each generated file contains:
- the first 1000 `[REDIAL:net1|net2]` ACCEPT rules of the base, none on port 5000 (the script stops if one is)
- the pass-all rule `-s 10.0.0.0/24 -j ACCEPT` (comment `[SWEEP:passall]`) inserted at position h
- rule IDs `R0001…R1001` renumbered, `FORWARD` policy DROP, no final-log

## 2. Run the sweep

```bash
sudo -v && ./sweep-passall.sh --tag sweep-prof --offset <OFFSET> [--reps 2] [--silence 5]
```

**Run it as a normal user**, after `sudo -v` (it uses `sudo` internally).

| Option | Default | Meaning |
| --- | --- | --- |
| `--tag` | `sweep-prof` | Output in `campagne/<tag>/` |
| `--dur` | `20` | Seconds per run |
| `--rates` | `100000,200000,400000,800000` | Rates in pps, one run each |
| `--reps` | `2` | Replicas per (h, rate) |
| `--silence` | `5` | Pause between runs, in seconds |
| `--rules-dir` | `rules_sweep` | Folder with `sweep_h*.rules` |
| `--offset` | `0` | RX clock offset in ns. **Always pass the current calibration.** |
| `--no-pkt` | off | Do not write the per-packet CSV (for averages-only campaigns) |
| `--keep-pcap` | off | Keep the pcaps (by default they are deleted after analysis) |

### For each ruleset (h)

1. Copies the ruleset to the firewall (`scp`) and loads it with `iptables-restore` in namespace `FW`.
2. Checks that there are **1001 rules** and that the pass-all is **at position h**. Otherwise it stops.

### For each rep and rate

1. Skips the run if `delta.csv` already exists. You can stop the sweep and relaunch it; it resumes where it left off.
2. Prints the expected load M = rate × h / 10⁶ evaluations/s. Above `KNEE_M` the point is marked **saturated** (out of the fit).
3. Resets the firewall counters, runs `listen.sh` in the background, then `udpramp` in `SX` (10.0.0.1 → 10.0.1.50:5000, 4-byte payload, `--cpu 2`, ramp `<dur>:<rate>`).
4. **σ check from the counters of this run** → `sigma_check.txt`:
   - only position h may have hits
   - the pass-all must be > 0
   - its count is compared with the packets `udpramp` sent (any difference = packets lost before the firewall)
5. Runs `compare-redial.py` → `delta.csv`, `delta.txt` (and `delta_pkt.csv.gz`).
6. Deletes the pcaps, then waits `--silence` seconds.

At the end it writes `campagne/<tag>/sweep_summary.csv`, with one row per (h, rate, rep) taken from the `tot` row:

```text
h,rate_pps,rep,mean_ns,std_ns,median_ns,p99_ns,loss
```

Plots: `plot-sweep.py` (`tools/plots/`).

## Output

```text
campagne/<tag>/
├── sweep_summary.csv
└── h0001/ h0051/ ... h1001/
    └── r100000_rep1/ ...
        udpramp.log  counters.txt  sigma_check.txt  delta.csv  delta.txt  delta_pkt.csv.gz
```

You need about 15 GB free while it runs, because the pcaps are deleted run by run.

## Requirements

- In the working folder: `listen.sh`, `udpramp` (`tools/udpramp/`) and `compare-redial.py` (`tools/compare-redial/`)
- SSH key access to the firewall, with passwordless `sudo` for `ip netns exec FW iptables*`
- Namespaces `SX`, `TAP`, `RX` on TS-P5 (`tools/namespace/`)

## Configuration

| Value in the script | x86 (TS-P360) | Raspberry Pi 5 |
| --- | --- | --- |
| `FW_HOST` | `drago@192.168.100.103` | `drago@192.168.100.104` |
| `KNEE_M` (M evaluations/s) | `115` | `20` |

`sweep-passall-pi.sh` (not included) differed only in these two lines. Edit them to run on the Pi.

Other fixed values in the script: probe `10.0.1.50:5000`, `--cpu 2`, `GRACE_BEFORE=2`, `GRACE_AFTER=4`.

`listen.sh` uses the interfaces `ens8191f3` (TAP) and `ens8191f2` (RX), tcpdump cores `CPU_TAP` / `CPU_RX`, and the env vars `TCPDUMP_BUF_KB` / `NIC_RING_RX`.

## Notes

- Before each run, delete `/tmp/et_*` and `/tmp/tcpdump_*.log`. Root-owned leftovers from earlier `sudo` runs make the runs fail. The script does this at startup.
- The script reminds you before starting: silence periodic timers on both hosts, and run only during the day.
- History: v3 uses separate runs per (h, rate, rep) and checks σ at every run. Derived from `campagna-redial.sh` + `run-experiment.sh`.
