# load-fw — load a ruleset on the firewall

`load-fw.sh` copies a ruleset (produced by `gen_fw_rules_v6.py`) from TS-P5 to the firewall
host and loads it into the `FW` network namespace, with a safety check before and after.

- **Runs on:** TS-P5, as a normal user (it uses SSH and remote `sudo`).
- **Target:** the `FW` namespace on the firewall host (TS-P360 for x86, the Raspberry Pi 5 for the embedded tests).

## Usage

```bash
./load-fw.sh <file.rules> [expected_rules]     # default expected_rules = 601
./load-fw.sh fw12575.rules                       # thesis PRE ruleset, 601 rules
```

## What it does

1. `scp` the file to `/tmp/fw_load.rules` on the firewall host.
2. **Dry run** with `iptables-restore --test`: if the file is broken, it stops here and the
   firewall keeps its previous rules.
3. Loads the ruleset with `iptables-restore`. The whole `filter` table is replaced and all
   counters restart from zero.
4. Checks that the `FORWARD` chain contains exactly `expected_rules` rules, otherwise it exits with an error.
5. Prints the number of rules, the policy and the **position of the first net2 rule** (h).

Example output:

```
[OK] fw12575.rules caricato: 601 regole, policy '-P FORWARD DROP', prima regola net2 in posizione 1
```

## Configuration

| Variable | Value in the thesis | Meaning |
| --- | --- | --- |
| `FW` | `drago@192.168.100.103` | SSH user and host of the firewall (x86, TS-P360) |
| | `drago@192.168.100.104` | Raspberry Pi 5 (the thesis used a copy of the script, `load-fw-pi.sh`, with only this line changed) |

## Requirements

- SSH key from TS-P5 to the firewall host (no password prompt).
- On the firewall host, `sudo` must work without an interactive password for
  `ip netns exec FW iptables…` (the commands run through `ssh` without a terminal).
- The `FW` namespace must already exist on the firewall host (see `tools/namespace/`).

## Known pitfalls

- With `--no-final-log` rulesets (600 rules) or other sizes, pass the expected count as the
  second argument, otherwise the check fails even if the load was successful.
- The POST ruleset is not loaded with this script: it is applied by REDIAL from the
  orchestrator (ieiitp97).
- Source comments and messages are in Italian.
