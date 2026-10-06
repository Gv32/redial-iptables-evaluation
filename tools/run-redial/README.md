# run-redial — `run-redial.sh`

Runs one REDIAL measurement on TS-P5:

1. Starts the capture (`tools/capture/listen-redial.sh`) in the background.
2. Waits 2 s.
3. Runs `sendpkts` in namespace `SX` with the given packet vectors, split and rate ramp.
4. Waits for the capture to finish.

The campaign scripts (`tools/campaign/`) call it once per run.

## Requirements

- `sendpkts`, compiled (`tools/sendpkts/`)
- `listen-redial.sh` (`tools/capture/`)
- `packets_net1.csv` / `packets_net2.csv` from `tools/gen-packets/`
- The namespaces `SX`, `TAP`, `RX` (and `DST`), from `tools/namespace/`
- The firewall under test already configured (`tools/load-fw/`, REDIAL on the orchestrator)

## Usage

```bash
chmod +x run-redial.sh
sudo ./run-redial.sh [options] --ramp DUR:R1,R2,...,RN

# 50/50 split, ramp up to 800k pps total (400k + 400k)
sudo ./run-redial.sh --split 50,50 --cpu 9 \
     --ramp 20:1,10,100,1000,10000,100000,400000,800000
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--net1 FILE` | `packets_net1.csv` | net1 vector |
| `--net2 FILE` | `packets_net2.csv` | net2 vector |
| `--split P1,P2` | `50,50` | net1/net2 share of the **total** rate, in % |
| `--cpu N` | `9` | Isolated core for `sendpkts` |
| `--out DIR` | `./captures` | Folder for the pcaps and the epoch file |
| `--bpf FILTER` | `udp` | Capture filter |
| `--ramp DUR:R1,...` | **required** | `DUR` = seconds per step; `Ri` = total pps of the step |

Generator time = `DUR × number of steps`; capture time = generator time + 2 s + `GRACE_AFTER`. In the example: 8 × 20 = 160 s of traffic and 165 s of capture.

### Environment variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `SENDPKTS` | `./sendpkts` | Path to the binary |
| `LISTEN_SH` | `./listen-redial.sh` | Path to the capture script |
| `GRACE_AFTER` | `3` | Extra capture seconds after the generator stops |
| `CAP_DST`, `IF_DST` | `0`, *(empty)* | Passed to the capture script (net2 sink) |

`sudo` drops environment variables, so put them after `sudo`:

```bash
sudo CAP_DST=1 IF_DST=ens8191f0 ./run-redial.sh --ramp ...
sudo GRACE_AFTER=20 ./run-redial.sh --ramp ...        # longer capture tail
sudo SENDPKTS=../sendpkts/sendpkts LISTEN_SH=../capture/listen-redial.sh ./run-redial.sh --ramp ...
```

On the testbed every file sits in `~/Test-Sigma`, so the defaults work there.

## Output (in `--out`)

- `tap_<STAMP>.pcap`, `rx_<STAMP>.pcap` (and `dst_<STAMP>.pcap`), from the capture script
- `ramp_start_<STAMP>.epoch`: the ramp start time, written by `sendpkts` (`--epoch-file`). Use it to line up the captures with the ramp steps.

When it finishes, the script prints the generator's exit code, the epoch and the latest pcaps. Ctrl+C (INT/TERM) also stops the capture, which still writes its data to disk.

## Configuration

- The sender namespace name `SX` is hardcoded.
- `--cpu 9` is the isolated core on TS-P5. Change it on other machines.
- Default paths are relative to the current folder.

## History and notes

- Derived from `run-experiment.sh` (switch characterization with `udpramp`). Changes:
  - `sendpkts` replaces `udpramp` as the generator
  - `sendpkts` writes the ramp start time to a file (`--epoch-file`)
  - the capture filter is plain `udp`
- `run-redial-long.sh` (not included) was identical except for a fixed `GRACE_AFTER=20`. Use `sudo GRACE_AFTER=20 ./run-redial.sh ...` instead.
- The script and the capture script each compute their own `STAMP`. They are usually the same second but can differ by 1 s.
- Because of `set -e`, if `sendpkts` exits with an error the script stops before the final `[done]` lines. The capture keeps running in the background until its time is up, and the pcaps are still written.
