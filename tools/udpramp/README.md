# udpramp — single-flow UDP rate generator

`udpramp` sends a **single UDP flow** (fixed 5-tuple) at a precisely controlled rate,
following a ramp of steps. Each packet carries a **monotonic sequence number** in the
first 4 bytes of the payload, used to pair the packets captured at the TAP and at the RX.

It was used for the testbed characterizations (port offset, switch, TAP, FW without rules,
FW with 500 dummy rules) and for the **pass-all sweep** (`sweep-passall.sh`), where a single
probe flow hits a pass-all rule at position h. It is also the base of `sendpkts`, which
uses the same real-time engine but replays pre-generated packet vectors.

- **Runs on:** TS-P5, inside the sender namespace `SX`, as root (or with `CAP_NET_RAW`).
- **Engine:** raw socket with `IP_HDRINCL`, pure busy-spin on `CLOCK_MONOTONIC`,
  `SCHED_FIFO` at maximum priority, `mlockall`, CPU pinning.

## Build

```bash
gcc -O3 -Wall -o udpramp udpramp.c -lrt
```

Only the standard C library is needed. The binary used in the thesis was built with this
exact command on TS-P5 (MD5 `4742a73de6996ce77da90aefd25a2846`; a different gcc version
may produce a different hash). The `-Wcomment` warning on line 3 is harmless: it comes from
a `\` at the end of a comment line in the usage example.

## Usage

```bash
sudo ip netns exec SX ./udpramp --src-ip 10.0.0.1 --dst-ip 10.0.1.50 \
     --src-port 5000 --dst-port 5000 --payload 4 --cpu 9 \
     --ramp 20:100000,200000,400000,800000
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--ramp DUR:R1,...,RN` | (required) | N steps of `DUR` seconds each, step i at `Ri` pps |
| `--src-ip IP` | `10.0.0.1` | source address |
| `--dst-ip IP` | `10.0.0.2` | destination address |
| `--src-port N` | 5000 | UDP source port |
| `--dst-port N` | 5000 | UDP destination port |
| `--payload N` | 4 | UDP payload size in bytes (min 4, max 1472) |
| `--cpu N` | 2 | pin to core N (`-1` = no pinning) |

## How it works

- **Packet:** built once as a template (TTL 64, UDP checksum = 0, allowed on IPv4).
  In the hot path only the sequence number, the IP ID and the IP checksum change
  (incremental checksum).
- **Payload:** the first 4 bytes are `seq` (big-endian, from 0, +1 for every send attempt);
  the remaining bytes are zero.
- **Start:** aligned to the next full second of `CLOCK_MONOTONIC` (reproducible start).
- **Timing:** interval = `1e9 / rate` ns (integer division), busy-wait until each deadline.
  A packet is sent only if its slot is **strictly before** the end of the step, so a step of
  N seconds at R pps sends exactly N·R packets. The next step starts exactly at the end of the
  previous one (no cumulative drift).
- **Errors:** `ENOBUFS` / `EAGAIN` are counted in `errs`; any other `sendto` error stops the run.
- **Output (stderr):** header with flow, payload and steps; per-step `sent`/`errs`
  (also cumulative); final totals.
