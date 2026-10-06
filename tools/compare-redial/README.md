# compare-redial — `compare-redial.py` + `compare-redial-win.py`

Offline analysis of the TAP and RX captures (`tools/capture/`). For every step of the rate ramp it measures:

- the **forwarding delay of the firewall**, Δ = t_RX − t_TAP
- the **real packet loss** between TAP and RX
- the **expected DENY** packets (dropped by the firewall on purpose) and any **leak** (DENY packets that reached RX)

| Script | What it gives |
| --- | --- |
| `compare-redial.py` | Statistics per ramp step (mean, std, median, p99 of Δ; loss), CSV and plots |
| `compare-redial-win.py` | The same Δ, split into time windows. It gives a robust Δ and flags disturbed windows. |

`compare-redial-win.py` **imports `compare-redial.py` from the same folder**, so keep the two files together.

## Requirements

- Python 3 (the pcap parser is pure Python, no scapy/dpkt)
- `matplotlib`, only for `--plot`
- Classic pcap files (µs or ns), as written by tcpdump. pcapng is not supported.
- The whole pcap is loaded into memory. Large captures (tens of millions of packets) need several GB of RAM.

## compare-redial.py

```bash
./compare-redial.py --tap captures/tap_<STAMP>.pcap --rx captures/rx_<STAMP>.pcap \
    --ramp 20:1,10,100,1000,10000,100000,400000,800000 \
    --rx-offset-ns <OFFSET> --rules fw1.rules \
    --csv delta_redial.csv --plot plots/

./compare-redial.py --selftest     # validates parser + pairing on synthetic data
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--tap`, `--rx` | — (required) | TAP and RX pcaps of the same run |
| `--ramp DUR:R1,...` | — | Same ramp as the run. Without it, everything counts as one step. |
| `--net1-cidr` / `--net2-cidr` | `10.0.1.0/24` / `10.0.2.0/24` | Subnets used to tell net1 from net2 (by destination IP) |
| `--seq-offset` / `--seq-len` | `0` / `4` | Position and length (bytes, big-endian) of the sequence number in the UDP payload |
| `--rx-offset-ns` | `0` | Clock offset of the RX NIC relative to the TAP NIC, subtracted from t_RX (calibration) |
| `--max-delay-ms` | `200` | Maximum pairing window. It must stay shorter than one wrap of the packet vector. |
| `--rules FILE` | — | Ruleset of the firewall: tells which packets are expected DENY |
| `--csv FILE` | — | Per-step CSV |
| `--per-packet-csv FILE` | — | One row per paired packet (`net, step, seq, t_tap, t_rx, delta_ns`) |
| `--plot DIR` | — | Writes `delta_vs_step.png`, `loss_vs_step.png`, `throughput_vs_step.png`, `delta_cdf.png` |
| `--log-scale` | off | Log x axis (rate) in the plots |

### How it works

- **Pairing.** `sendpkts` uses many 5-tuples and a per-net sequence number (0..N−1, from `gen_packets_v2.py`) in the first 4 bytes of the payload. That number repeats at every wrap of the vector. Packets are paired by (net, seq): for each RX packet the script takes the **last TAP packet with the same seq before t_RX**, inside the window, and uses each TAP copy only once.

  This works because two copies of the same seq are a full vector wrap apart (tens of ms at 800k pps), while the firewall delay is a few µs. A lost copy does not shift the others.
- **Steps.** t0 is the first TAP timestamp; step = ⌊(t − t0) / DUR⌋. Hardware timestamps are not real epoch times, so alignment is relative.
- **Expected DENY.** With `--rules`, the destination ports of the `[REDIAL:wildcard] ... --dport N -j DROP` rules are expected DENY:
  - they are counted in `deny_fw` and **excluded from the loss**
  - a DENY packet seen at RX is a **leak** (must be 0; the script warns)
- **Rows.** One row per net and step, plus a `tot` row (`net = 0` in the CSV): the Δ of the whole firewall, weighted on the paired packets of both nets. Compare the `tot` row of the PRE run with the POST run.

### Output (stdout and `--csv`)

`net, step, rate_pps, tap_acc, deny_fw, rx_matched, leak, loss, loss_pct, delta_mean_ns, delta_std_ns, delta_median_ns, delta_p99_ns`

- `tap_acc`: legitimate packets seen at the TAP (the loss denominator)
- `loss = tap_acc − rx_matched`

## compare-redial-win.py

**Why it exists.** During the day the testbed sometimes shows a disturbance lasting a few seconds. It inflates std and p99 of the whole run while barely moving the mean. This script splits each step into `--win`-second windows and reports:

- the **median of the window means**, used as the robust Δ of the run
- the **median of the window stds**, used as the real dispersion
- the number of **dirty windows** (std above a threshold). If ≤ 25% of the windows are dirty (on the `tot` row), the run is usable; otherwise repeat it.

```bash
./compare-redial-win.py --tap captures/tap_X.pcap --rx captures/rx_X.pcap \
    --ramp 60:400000 --rx-offset-ns <OFFSET> --rules fw17525.rules \
    --std-warn-us 25 --csv win.csv

./compare-redial-win.py --selftest
```

It accepts the same `--tap/--rx/--ramp/--net*-cidr/--seq-*/--rx-offset-ns/--max-delay-ms/--rules` options, plus:

| Option | Default | Meaning |
| --- | --- | --- |
| `--win` | `5` | Window length in seconds |
| `--std-warn-us` | auto | Dirty-window threshold. Thesis values: **40 PRE / 25 POST**. Default: 2 × median of the window stds. A 25 µs floor always applies (the background noise of clean windows is 18–24 µs). |
| `--csv FILE` | — | One row per window: `net, step, rate_pps, win, t_start_s, count, mean_ns, std_ns, med_ns, p99_ns, flag` |

## Configuration

- `--rx-offset-ns`: **always pass the most recent calibrated offset.** The examples inside the scripts use `-11973`, an old value. The last calibration used in the thesis is **−11764 ns**. Re-calibrate if the NICs or cables change.
- Subnets default to the x86 testbed (net1 = 10.0.1.0/24, net2 = 10.0.2.0/24).
- `--rules` must be the ruleset actually loaded on the firewall for that run.

## History

- Derived from `compare-tap-rx.py` (switch characterization / port offset with `udpramp`). That one paired packets on a single fixed 5-tuple with a unique sequence number. The pcap front-end was rewritten for `sendpkts` (many 5-tuples, per-net seq with wrap-around); the plots are the same.
- Added later: expected-DENY handling via `--rules`, leak detection, and the aggregate `tot` row (July 2026).
- `compare-redial-win.py` was added for the window-based robust statistics. It does not modify `compare-redial.py`; it imports it.
