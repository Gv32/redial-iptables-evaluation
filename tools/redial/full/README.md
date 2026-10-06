# redial/full — full two-firewall REDIAL (`redial_v5.py`)

Full REDIAL implementation (Durante et al., IEEE TIFS 2021) for **two firewalls**:

- **FW1^** (upstream, lightened): rules that concern only the redistributed domain d2 are removed, and a shortcut `-d <d2> -j ACCEPT` is added.
- **FW2^** (downstream): receives FW1's rules for d2 in a custom chain `REDIAL_A_0`, evaluated before FW2's original rules.

The thesis measurements use the FW1-only emulation in `../` (`redial_fw1_only.py`). FW1's behaviour is the same, but there FW2 is ignored.

## Files

| File | Role |
| --- | --- |
| `redial_v5.py` | The algorithm (`redial()`), v5 |
| `redialUtils.py` (v4.2) | `iptables-xml` parser, data classes, `iptables-save` serializer. Identical to `../RedialUtils.py`; the lowercase name is the one imported here. |
| `run_redial.py` | CLI: reads `fw1.xml` / `fw2.xml`, calls `redial()`, writes `fw1.new.rules` / `fw2.new.rules` |
| `inventory.sh` | Configuration (domains, IPs, namespaces, user, password file) and SSH helpers (`fw_run`, `fw_pipe`, `fw_scp_to`); creates `WORKDIR` |
| `collect.sh` | `iptables-save` of FW1 and FW2 (inside their namespaces) → `fw{1,2}.backup.rules` + `fw{1,2}.xml` |
| `start.sh` | Full workflow, step by step: collect → REDIAL → copy + dry run → apply → check |

## Requirements (bastion = ieiitp97)

- Python 3, `iptables-xml`, `sshpass`
- A password file for the FW user (`PASS_FILE`). The sudo password is assumed to be the same as the SSH one. **Never commit it.**
- `chmod +x *.sh *.py`

## Usage

```bash
cd ~/redial
bash start.sh          # or run its sections one by one
```

`start.sh` sections:
1. `source inventory.sh` (creates `WORKDIR=~/redial/runs/<timestamp>`), with a check that `FW1_NETNS` / `FW2_NETNS` are set
2. `./collect.sh` → backups + XML
3. `./run_redial.py` → `fw1.new.rules`, `fw2.new.rules`
4. Copies the files to `/tmp` on the FWs and runs `iptables-restore --test`. If you see `[ABORT]`, **do not apply** on that FW.
5. `iptables-restore` on both FWs (inside the namespaces)
6. Shows the first FORWARD rules and the `REDIAL_A_0` chain

The rules are applied **in RAM only** (not persistent across reboots). **Rollback is manual:** restore `fw1.backup.rules` / `fw2.backup.rules` from `WORKDIR` with `ip netns exec <netns> iptables-restore`.

### `run_redial.py` on its own

```bash
./run_redial.py --fw1-xml fw1.xml --fw2-xml fw2.xml \
    --d0 10.0.0.0/24 --d2 10.0.2.0/24 --dn 10.0.1.0/24 \
    --fw2-iface eth0 --out-fw1 fw1.new.rules --out-fw2 fw2.new.rules
```

- `--fw2-iface`: FW2's interface (inside its namespace) towards FW1. Repeat it once per `--fw2-xml`, in the same order. If you omit it, the jump matches `-s d0` (v4 behaviour).
- Run `./run_redial.py --help` for all options.

## Configuration (`inventory.sh`)

| Variable | Value | Meaning |
| --- | --- | --- |
| `D0_CIDR` | `10.0.0.0/24` | Source domain (sender, TS-P5) |
| `D1_CIDR` | `10.0.3.0/24` | FW1 ↔ FW2 link (`FW1_INNER_IP` 10.0.3.1, `FW2_INNER_IP` 10.0.3.2) |
| `D2_LIST_CIDR` | `10.0.2.0/24` | Redistributed domain(s) (behind FW2) |
| `DN_LIST_CIDR` | `10.0.1.0/24` | Domain(s) that stay on FW1 |
| `FW1_IP` / `FW1_NETNS` | `192.168.100.103` / `FW` | FW1 (TS-P360) |
| `FW2_IP` / `FW2_NETNS` | `192.168.100.104` / `FW2` | FW2 |
| `FW2_UPSTREAM_IFACES` | `eth0` | FW2 interface towards FW1 |
| `GEN_IP` | `192.168.100.101` | Traffic generator (TS-P5) |
| `SSH_USER` | `drago` | SSH user |
| `PASS_FILE` | *(path)* | Password file, outside the repo |

## History

- **v2 → v4**: earlier versions (not included).
- **v5**: new parameter `fw2_upstream_ifaces`. The jump `FW2.FORWARD → REDIAL_A_<j>` now matches on the **input interface** (`-i <iface>`) instead of `-s d0`. Traffic coming through FW1 is caught whatever its source IP, and intra-leaf traffic skips block A. `redialUtils.py` v4.2 adds the `in_iface` field this needs.
- `deploy.sh` (an older apply script with a 60 s automatic rollback) is not included: its rollback restored the rules outside the firewall namespace.
