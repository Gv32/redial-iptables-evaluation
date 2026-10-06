# sendpkts — deterministic packet sender

`sendpkts` replays the two packet vectors produced by `gen_packets_v2.py`
(`packets_net1.csv`, `packets_net2.csv`) towards the firewall at a precisely controlled rate.
Each CSV row becomes a ready-made IPv4 + UDP packet in memory (src, sport, dst, dport and
payload taken **exactly** from the file) and is sent through a raw socket. It is the traffic
generator used in all REDIAL campaigns.

It is derived from `udpramp.c` and uses the same real-time engine: raw socket with
`IP_HDRINCL`, pure busy-spin on `CLOCK_MONOTONIC`, `SCHED_FIFO` at maximum priority,
`mlockall` and CPU pinning.

- **Runs on:** TS-P5, inside the sender namespace `SX`, as root (or with `CAP_NET_RAW`).
- **Input:** the CSV vectors of `gen_packets_v2.py`.
- **Called by:** `run-redial.sh` (which also starts the TAP/RX captures).

## Build

```bash
gcc -O3 -Wall -o sendpkts sendpkts.c -lrt
```

Only the standard C library is needed. The binary used in the thesis campaigns was built with
this exact command on TS-P5
## Usage

```bash
sudo ip netns exec SX ./sendpkts --net1 packets_net1.csv --net2 packets_net2.csv \
     --split 50,50 --cpu 9 --ramp 60:400000
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--ramp DUR:R1,...,RN` | (required) | N steps of `DUR` seconds each, step i at a **total** rate of `Ri` pps |
| `--net1 FILE` | `packets_net1.csv` | vector for net1 (`10.0.1.0/24`) |
| `--net2 FILE` | `packets_net2.csv` | vector for net2 (`10.0.2.0/24`) |
| `--split P1,P2` | `50,50` | share of the total rate sent to net1 / net2 |
| `--cpu N` | 2 | pin the sender to core N (`-1` = no pinning); the campaigns use the isolated core 9 |
| `--epoch-file F` | — | write the `CLOCK_REALTIME` start time (`sec.nsec`) to F, used to align the captures |
| `--dry-run` | off | do not send anything (checks the logic and counts, no root needed) |

**Relation with ρ** (fraction of traffic towards net2): `--split (1−ρ)·100,ρ·100`.
For example ρ = 0.25 → `--split 75,25`.

## How it works

- **Start:** after loading the vectors, the sender waits for the next full second of
  `CLOCK_MONOTONIC` (reproducible start), then writes the epoch file if requested.
- **Timing:** inter-packet interval = `1e9 / rate` ns (integer division), busy-wait until
  each deadline. Each step ends exactly after `DUR` s (no cumulative drift between steps).
- **Split:** deterministic accumulator, no randomness. With `--split 50,50` net1 and net2
  alternate exactly; with `75,25` one packet in four goes to net2.
- **Vectors:** each vector is read in order and **restarts from the first packet** when it
  reaches the end (wrap-around), so the per-net `seq` repeats every N packets.
- **Packets:** IPv4 header built by the sender (TTL 64, IP ID incrementing per vector from 0,
  correct IP checksum); UDP checksum = 0 (allowed on IPv4, not checked); payload = the
  `payload_hex` column (max 2048 bytes; the `plen` column is ignored).
- **Errors:** `ENOBUFS` / `EAGAIN` are counted in `errs` (packet not sent); any other
  `sendto` error stops the run.

## Output (stderr)

A header with vectors, split and steps; one line at the start and at the end of each step
with the packets sent to net1/net2 and the errors; final totals (`inviati net1`,
`inviati net2`, `totale`, `errori`). `run-redial.sh` saves this output with the captures.
