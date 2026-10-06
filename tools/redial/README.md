# redial — FW1-only REDIAL (`redial_fw1_only.py` + scripts)

Emulates the effect of REDIAL **on the upstream firewall only (FW1)**. It builds FW1^, the lightened ruleset FW1 would have after REDIAL, and applies it.

- Rules that concern only the redistributed domain d2 are **removed** from FW1.
- A **shortcut** `-d <d2> -j ACCEPT` is inserted at the position of the first rule that touches d2.
- FW2 is ignored by design. No FW2 ruleset and no `REDIAL_A_*` chain are produced.

FW1's behaviour is meant to be identical to the full REDIAL (`full/`). This is the version used for all thesis measurements. It runs on **ieiitp97** and drives FW1 over SSH.

## Files

| File | Role |
| --- | --- |
| `redial_fw1_only.py` | The algorithm: reads FW1 as XML and writes FW1^ in `iptables-save` format |
| `RedialUtils.py` (v4.2) | Library shared with the full REDIAL: `iptables-xml` parser, data classes, `iptables-save` serializer |
| `inventory.sh` | Configuration: domains, FW1 address, user, password file, `WORKDIR` |
| `lib.sh` | SSH/SCP helpers (`fw1`, `fw1_sudo`, `fw1_put`) via `sshpass` |
| `run-fw1-only.sh` | **One-shot command**: collect → generate → validate → apply |
| `start.sh` | Menu: `prepare`, `post`, `pre`, `pre-last`, `status` and the single steps |
| `collect-fw1.sh` | `iptables-save` of FW1 → `fw1.backup.rules`, converted with `iptables-xml` → `fw1.xml` |
| `generate-fw1-only.sh` | Runs `redial_fw1_only.py` → `fw1.redial-only.rules`; shows the shortcut and the rule counts |
| `validate-fw1-only.sh` | `iptables-restore --test` on FW1 |
| `apply-fw1-only.sh` | Dry run, then `iptables-restore` of FW1^ on FW1 |
| `rollback-fw1.sh` | Restores `fw1.backup.rules` from the current `WORKDIR` |
| `pre-last.sh` | Rollback using the latest run that has a backup |
| `status-fw1.sh` | Tests SSH and sudo; shows the first rules and whether the shortcut is present |

## Requirements (ieiitp97)

- Python 3, `iptables-xml`, `sshpass`
- A password file for the FW1 user (`PASS_FILE`, default `~/redial/.fwpass`). **It is not part of this repo: never commit it.**
- Run `chmod +x *.sh redial_fw1_only.py` once after downloading

## Usage

```bash
# FW1 must be in PRE state (original ruleset)
unset WORKDIR && ./run-fw1-only.sh       # what the campaigns use

# step by step
unset WORKDIR; source ./inventory.sh
./start.sh prepare                       # collect + generate + validate, no apply
./start.sh post                          # apply FW1^

# back to PRE
./start.sh pre-last                      # latest run with a backup
export WORKDIR=~/redial-single-fw/runs/YYYYMMDD-HHMMSS && ./start.sh pre

./start.sh status
```

Each run creates `runs/YYYYMMDD-HHMMSS/` with `fw1.backup.rules` (PRE), `fw1.xml` and `fw1.redial-only.rules` (POST).

**Do not run it twice in a row.** If FW1 is already in POST, roll back first; otherwise the "backup" would be the POST ruleset.

### `redial_fw1_only.py` on its own

```bash
./redial_fw1_only.py --fw1-xml fw1.xml --d2 10.0.2.0/24 --dn 10.0.1.0/24 \
    --out-fw1 fw1.redial-only.rules [--log-strategy move|keep|duplicate]
```

`--d2` and `--dn` can be repeated.

## How the algorithm works

It scans FW1's rules in order and looks **only at the destination** of each rule.

| Rule | On FW1^ |
| --- | --- |
| The first rule that touches d2 (dst overlaps d2, or no dst = wildcard) | The shortcut `-A FORWARD -d <d2> -j ACCEPT` is inserted **before** it |
| dst overlaps dn, or no dst (wildcard) | **Kept** |
| dst only in d2 | **Removed** (in the full REDIAL it would move to FW2) |
| Non-terminating target (LOG, NFLOG, …) | `move` (default): treated like the other rules. `keep` / `duplicate`: always kept. |

Because of this, wildcard packets towards d2 are accepted by the shortcut: this is the "leak" that `sigma_collector_subnet.py --post` handles. Only the first table of the dump is processed (`filter` on the testbed). The chain policies are copied unchanged.

## Configuration (`inventory.sh`, all overridable via env)

| Variable | Default | Meaning |
| --- | --- | --- |
| `D0_CIDR` | `10.0.0.0/24` | Source domain (sender) |
| `DN_CIDR` | `10.0.1.0/24` | Domain that stays on FW1 (net1) |
| `D2_CIDR` | `10.0.2.0/24` | Redistributed domain (net2) |
| `FW1_MGMT` | `192.168.100.103` | FW1 management IP (use `192.168.100.104` for the Raspberry Pi 5) |
| `FW1_NETNS` | `FW` | FW1 namespace |
| `SSH_USER` | `drago` | SSH user on FW1 |
| `PASS_FILE` | `~/redial/.fwpass` | Password file for SSH/sudo |
| `WORKDIR` | `runs/<timestamp>` | Run folder (new one if unset) |

## Notes

- The full two-firewall REDIAL (`redial_v5.py`) is in [`full/`](full/).
- `redialUtils.py` (lowercase) was an identical copy and is not included here. The import uses `RedialUtils`.
