# capture — `listen-redial.sh`

Captures packets with hardware timestamps, in parallel, on the TS-P5 testbed namespaces:

- **TAP**: a copy of the traffic entering the firewall
- **RX**: the net1 sink
- **DST** (optional): the net2 sink, used only in the 2-FW topology

It is normally started by `tools/run-redial/run-redial.sh`, but it can also run on its own.

## Requirements

- The namespaces `TAP`, `RX` (and `DST`), created with `tools/namespace/`
- `tcpdump` with NIC hardware timestamps (`-j adapter_unsynced`, nanosecond precision). On TS-P5 the NICs are Intel I350.
- `ethtool`, `chrt`, `taskset`, and sudo rights (the script calls `sudo` internally)
- Optional: `capinfos` (Wireshark), for exact packet counts

## Usage

```bash
chmod +x listen-redial.sh
./listen-redial.sh [DURATION] [BPF] [OUTDIR]

./listen-redial.sh 60                                # 60 s, filter "udp", ./captures
./listen-redial.sh 30 "udp port 5000"                # same filter as the old listen.sh (udpramp)
CAP_DST=1 IF_DST=ens8191f0 ./listen-redial.sh 60     # also capture the net2 sink
```

| Argument | Default | Meaning |
| --- | --- | --- |
| `DURATION` | `30` | Capture length in seconds |
| `BPF` | `udp` | tcpdump filter |
| `OUTDIR` | `./captures` | Output folder |

## What it does

1. **Preflight**: sets the NIC RX ring to `NIC_RING_RX` and turns off GRO/LRO/TSO/GSO. These offloads merge frames before capture, which would distort timestamps and counts.
2. **Snapshot**: saves the NIC drop counters (`ethtool -S`: `rx_missed_errors`, `rx_fifo_errors`, `rx_over_errors`, `rx_dropped`, …).
3. **Capture**: starts one `tcpdump` per interface, inside its namespace. Each runs as SCHED_FIFO 50 on its own core, with a 512 MB buffer, nanosecond timestamps and `-nn`.
4. **Stop**: after `DURATION` it sends SIGINT. tcpdump then writes out the remaining packets and prints its statistics.
5. **Report**:
   - packets received/dropped by the kernel
   - NIC counter deltas (hardware/driver drops)
   - packets captured (`received by filter`) and file sizes

**Check before using a run:** the kernel should report 0 dropped packets, and there should be no NIC delta. If either shows drops, the capture lost packets and the run's loss figures are not reliable.

## Output

- `OUTDIR/tap_<STAMP>.pcap`, `rx_<STAMP>.pcap`, `dst_<STAMP>.pcap` (`STAMP` = `YYYYmmdd_HHMMSS`)
- Logs in `/tmp/tcpdump_{tap,rx,dst}.log` and `/tmp/et_{pre,post}_*.txt`. They are overwritten on every run.

## Configuration (TS-P5 values)

Every value can be overridden with an environment variable, so no code changes are needed.

| Variable | Default | Notes |
| --- | --- | --- |
| `NS_TAP` / `IF_TAP` | `TAP` / `ens8191f3` | No IP, promiscuous |
| `NS_RX` / `IF_RX` | `RX` / `ens8191f2` | 10.0.1.3/24 (net1 sink) |
| `NS_DST` / `IF_DST` | `DST` / *(empty)* | `ens8191f0` on TS-P5, 10.0.2.2/30 (net2 sink) |
| `CAP_DST` | `0` | `1` = also capture DST (requires `IF_DST`) |
| `CPU_TAP` / `CPU_RX` / `CPU_DST` | `4` / `6` / `8` | Must differ from the sender core (9) |
| `TCPDUMP_BUF_KB` | `524288` | 512 MB |
| `NIC_RING_RX` | `4096` | Maximum for the I350 |

## History and notes

- Derived from `listen.sh` (switch characterization / port offset with `udpramp`). That version filtered on `port 5000` and captured only TAP and RX. The default filter is now plain `udp`, because `sendpkts` uses many destination ports taken from the ruleset.
- The previous version, `listen.sh` (port 5000 only, TAP + RX, no namespace parameters), is kept in `legacy/` for reference.
- tcpdump is started as a direct child of the shell. An earlier version used a `$(...)` subshell: tcpdump was orphaned and `wait` returned before it had finished writing the file.
- Packet counts come from tcpdump's `received by filter` line. The old `tcpdump -r | wc -l` stalled for minutes on multi-million-packet captures (the "hung listener" problem).
- Known issue: the `no_buff_count` pattern probably never matches the igb counter `rx_no_buffer_count`, so that counter is never shown. `rx_missed_errors` is reported correctly.
