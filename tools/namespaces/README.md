# namespace — testbed network namespaces (TS-P5 side)

Scripts that create the Linux network namespaces of the measurement host (TS-P5).
Each physical port of the host is moved into its own namespace, so that the sender, the
capture point and the receivers are fully isolated from each other and from the host's own
network stack.

| Script | Purpose | Needed for |
| --- | --- | --- |
| `creation-namespace.sh` | creates `SX`, `TAP`, `RX` (and `DST`) | **always** (single-FW testbed) |
| `dst-up.sh` | creates only `DST`, configured as a strict sink for the d2 path | only the 2-FW testbed |

- **Runs on:** TS-P5, as root.
- **When:** after every reboot, before any experiment (namespaces are not persistent).

## Topology (TS-P5 side)

| Namespace | Interface | Address | Default route | Role |
| --- | --- | --- | --- | --- |
| `SX` | `enp1s0f1` | `10.0.0.1/24` | `10.0.0.3` (FW1 inside) | sender (`sendpkts`, `udpramp`) |
| `TAP` | `ens8191f3` | none, promiscuous | — | passive capture of the traffic entering FW1 |
| `RX` | `ens8191f2` | `10.0.1.3/24`, promiscuous | `10.0.1.1` (FW1.out) | sink of net1, capture of the traffic leaving FW1 |
| `DST` | `ens8191f0` | `10.0.2.2/30`, promiscuous | `10.0.2.1` (FW2.out) | sink of net2 (d2), not used in the single-FW testbed |

The `ens8191f*` ports belong to the Intel I350 NIC, which provides the hardware timestamps
used by the captures. IP forwarding is disabled in all the namespaces (they are leaves).

## Usage

```bash
sudo ./creation-namespace.sh up       # create namespaces and move the interfaces (default)
sudo ./creation-namespace.sh status   # addresses and routes of each namespace
sudo ./creation-namespace.sh down     # move the interfaces back to the root ns and delete

sudo ./dst-up.sh up|status|down       # only for the 2-FW testbed
```

Both scripts are idempotent: running `up` twice does no harm.

## What `dst-up.sh` adds compared to `creation-namespace.sh`

- `rp_filter=0` and `accept_local=1` on the interface, to accept frames not addressed to the sink;
- iptables in `DST`: INPUT drops everything not addressed to `10.0.2.2`, FORWARD policy DROP
  (no INPUT logs during the runs);
- a detailed `status` (link, routes, forwarding, INPUT counters).

## Configuration

The values are written at the top of each script. Change them if the hardware is different:

| Variable | Value in the thesis | Meaning |
| --- | --- | --- |
| `IF_SX` | `enp1s0f1` | sender port |
| `IF_TAP` | `ens8191f3` | TAP capture port |
| `IF_RX` | `ens8191f2` | RX capture/sink port |
| `IF_DST` / `IF` | `ens8191f0` | d2 sink port |
| addresses / gateways | see the table above | must match the FW configuration |

## Known pitfalls

- **The PHC clocks of the NIC restart at every power cycle:** after recreating the
  namespaces, recalibrate the TAP↔RX offset before any new campaign.
- `down` moves the interfaces back to the root namespace but does not restore their old addresses.
- `creation-namespace.sh` also creates `DST`: this is harmless in the single-FW testbed.
- Source comments and messages are in Italian.
