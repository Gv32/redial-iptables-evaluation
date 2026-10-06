# gen-packets — packet vector generator

`gen_packets_v2.py` reads a FW1 ruleset produced by `gen_fw_rules_v6.py` and generates
**two deterministic vectors of UDP packets**, one for net1 (`10.0.1.0/24`) and one for
net2 (`10.0.2.0/24`). Every packet is built so that it **matches a specific rule** of the
firewall: source in `10.0.0.0/24`, UDP, destination port of the rule, and a concrete destination
host inside the rule's destination. The vectors are then replayed by the traffic generator
(`sendpkts`, see `run-redial.sh`).

- **Runs on:** any machine with Python 3 (standard library only, no dependencies).
- **Input:** a ruleset with the `[REDIAL:net1|net2|wildcard]` comment tags.
- **Output used by:** `sendpkts` / `run-redial.sh` (traffic), `sigma_collector_subnet.py`
  (`--packets-net1/--packets-net2`, real wildcard fractions), `sigma_simulate.py` (offline σ check).

## How the vectors are built

For each net, `--count` packets are generated:

1. **Wildcard noise:** `round(count × --wildcard-frac)` packets (default 5%) go to the
   wildcard ports of the ruleset, spread evenly across the ports, to a random host of the net.
2. **Legitimate traffic:** the remaining packets are spread **evenly across all the ACCEPT
   rules of that net** (each rule gets the same number of packets, ±1), to a random host
   inside the rule's destination.
3. The list is **shuffled** with the seeded RNG, so the rule order inside the vector is random.

Other details:

- **Destination hosts** never use the reserved octets `.0 .1 .2 .3 .255`.
- **Source:** fixed `10.0.0.1` (default), or `--src sweep` for random hosts of `10.0.0.0/24`.
- **Source port:** random in `[--sport-min, --sport-max]` (up to 4 retries to avoid
  repeating the same 4-tuple; uniqueness is not guaranteed).
- **Payload:** the first 4 bytes are the **per-net sequence number** (big-endian, `1..N`),
  followed by filler bytes if `--payload-bytes` > 4.
  `compare-redial.py` uses this sequence number to pair TAP and RX packets.
- **Verdict:** `ACCEPT` for legitimate packets. For wildcard packets it is the **real action**
  of the wildcard rule (`ACCEPT` or `DROP`).

The generation is **fully deterministic**: same ruleset + same `--seed` + same `--count`
→ byte-identical vectors.

## Usage

```bash
python3 gen_packets_v2.py -r <file.rules> [options]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `-r, --rules` | (required) | input ruleset |
| `--out-net1` | `packets_net1.csv` | output vector for net1 |
| `--out-net2` | `packets_net2.csv` | output vector for net2 |
| `--count N` | 10000 | packets per vector |
| `--seed N` | 42 | RNG seed |
| `--wildcard-frac F` | 0.05 | fraction of packets sent to wildcard ports |
| `--payload-bytes L` | `4` | payload size in bytes; a list like `4,64,512` is used cyclically |
| `--payload-hex HEX` | — | fixed payload for every packet (**removes the sequence number**) |
| `--src IP\|sweep` | `10.0.0.1` | source address |
| `--sport-min / --sport-max` | 1024 / 65535 | source port range |
| `--format` | `csv` | `csv` or `jsonl` (with `jsonl` the extension is replaced) |

## Output format (CSV)

```
seq,net,proto,src,sport,dst,dport,plen,verdict,rule_id,label,payload_hex
```

| Column | Meaning |
| --- | --- |
| `seq` | per-net sequence number, 1..N (also in the first 4 payload bytes) |
| `net` | `net1` or `net2` |
| `src`, `sport`, `dst`, `dport`, `proto` | packet header (`proto` is always `udp`) |
| `plen` | payload length in bytes |
| `verdict` | expected FW verdict: `ACCEPT`, or the wildcard action |
| `rule_id` | `R####` of the matched ACCEPT rule (empty for wildcard packets) |
| `label` | rule description, or `wildcard-<port>` |
| `payload_hex` | payload in hex |

At the end the script prints a summary per net: legitimate/wildcard packets, rules covered,
unique 5-tuples and unique packets.

## Example (thesis campaigns)

```bash
python3 gen_fw_rules_v6.py --seed 42 --order n2n1 --limit 601 --net-ratio 50,50 \
    --wildcard-rules 50 --wildcard-style pairs --wildcard-action accept -o fw15050.rules
python3 gen_packets_v2.py -r fw15050.rules --count 10000 --seed 42
# -> packets_net1.csv, packets_net2.csv (10000 packets each, ~34-35 packets per ACCEPT rule)
```
