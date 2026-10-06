#!/usr/bin/env python3
# compare-redial.py - differenza timestamp TAP<->RX per il banco REDIAL (sendpkts).
# ----------------------------------------------------------------------------
# Stesso scopo di compare-tap-rx.py (Offset porte / Caratterizzazione switch):
# misurare il ritardo di forwarding del FW come Delta = t_rx - t_tap per ogni
# step della rampa, piu' la loss (pacchetti persi tra TAP e RX).
#
# Differenza chiave rispetto a udpramp/compare-tap-rx.py:
#   * udpramp usa una 5-tupla FISSA + seq monotono UNICO -> pairing banale.
#   * sendpkts usa MOLTE 5-tuple (dal ruleset) e il seq nel payload (primi 4
#     byte, big-endian) e' quello PER-NET di gen_packets (0..N-1) che, col
#     WRAP-AROUND, si RIPETE a ogni giro del vettore.
# Soluzione: si appaia per (net, seq) sfruttando che il TAP vede TUTTO lo stream
# in ordine e che due copie dello stesso seq distano un giro intero di vettore
# (decine di ms a 800k pps) >> ritardo del FW (us): per ogni ricezione all'RX si
# prende la trasmissione al TAP "ultima precedente entro la finestra" -> match
# corretto anche con perdita (una copia persa non sfasa le altre).
#
# Il net si deduce dall'IP dst (net1 = 10.0.1.0/24, net2 = 10.0.2.0/24).
# Oltre alle righe per-net viene emessa una riga aggregata 'tot' (net=0 nel
# CSV) per ogni step: Delta medio dell'INTERO FW, pesato sui pacchetti
# appaiati delle due net -> e' il valore totale da accostare al guadagno
# Gamma confrontando la run PRE con la run POST (agg. lug 2026).
# La parte di GRAFICI e' la stessa gia' usata (curve I/O, loss, CDF del Delta):
# cambia solo il front-end che estrae (seq, net, ts) dai pcap.
#
# Verdetti attesi (--rules fw1.rules): le dport delle regole [REDIAL:wildcard]
# DROP sono DENY attese -> contate in 'deny' ed ESCLUSE dalla loss reale;
# i DENY visti all'RX sono 'leak' (devono essere 0).
#
# Uso tipico:
#   ./compare-redial.py --tap captures/tap_*.pcap --rx captures/rx_*.pcap \
#       --ramp 20:1,10,100,1000,10000,100000,400000,800000 \
#       --rx-offset-ns -11973 --rules fw1.rules \
#       --csv delta_redial.csv --plot plots/
#
# Selftest (nessun pcap reale, valida parser+pairing su dati sintetici):
#   ./compare-redial.py --selftest

import argparse
import ipaddress
import os
import re
import statistics
import struct
import sys
from collections import defaultdict

# ----------------------------- ruleset (verdetti attesi) -------------------
RE_WILD = re.compile(r'--dport (\d+) -j DROP')


def load_wildcard_ports(path):
    """Porte delle regole [REDIAL:wildcard] DROP -> verdetto atteso DENY."""
    ports = set()
    with open(path) as fh:
        for line in fh:
            if '[REDIAL:wildcard]' in line:
                m = RE_WILD.search(line)
                if m:
                    ports.add(int(m.group(1)))
    return ports


# ----------------------------- pcap reader ---------------------------------
MAGIC_US = 0xa1b2c3d4
MAGIC_NS = 0xa1b23c4d


def _l3_offset(pkt, linktype):
    """Ritorna l'offset del header IPv4 nel frame, o None se non IPv4."""
    if linktype == 1:                      # EN10MB (Ethernet)
        if len(pkt) < 14:
            return None
        eth = struct.unpack('>H', pkt[12:14])[0]
        o = 14
        while eth in (0x8100, 0x88a8):     # VLAN tag(s)
            if len(pkt) < o + 4:
                return None
            eth = struct.unpack('>H', pkt[o + 2:o + 4])[0]
            o += 4
        return o if eth == 0x0800 else None
    if linktype == 101:                    # RAW (IP grezzo)
        return 0
    if linktype == 113:                    # LINUX_SLL
        if len(pkt) < 16:
            return None
        return 16 if struct.unpack('>H', pkt[14:16])[0] == 0x0800 else None
    if linktype == 276:                    # LINUX_SLL2
        if len(pkt) < 20:
            return None
        return 20 if struct.unpack('>H', pkt[0:2])[0] == 0x0800 else None
    return None


def _classify(dst_int, nets):
    for net_id, net in nets:
        if int(net.network_address) <= dst_int <= int(net.broadcast_address):
            return net_id
    return None


def parse_packet(pkt, linktype, seq_off, seq_len, nets):
    o = _l3_offset(pkt, linktype)
    if o is None or len(pkt) < o + 20:
        return None
    vihl = pkt[o]
    if (vihl >> 4) != 4:
        return None
    ihl = (vihl & 0x0f) * 4
    if pkt[o + 9] != 17:                    # solo UDP
        return None
    dst_int = struct.unpack('>I', pkt[o + 16:o + 20])[0]
    net_id = _classify(dst_int, nets)
    if net_id is None:
        return None
    uo = o + ihl
    if len(pkt) < uo + 8:
        return None
    dport = struct.unpack('>H', pkt[uo + 2:uo + 4])[0]
    payload = pkt[uo + 8:]
    if len(payload) < seq_off + seq_len:
        return None
    seq = int.from_bytes(payload[seq_off:seq_off + seq_len], 'big')
    return net_id, seq, dport


def read_pcap(path, seq_off, seq_len, nets, wildcard_ports):
    """Ritorna dict net_id -> {'acc': [(seq, ts)], 'deny': [(seq, ts)]} ordinati per ts.
    'deny' = dport in wildcard_ports (verdetto atteso DROP sul FW)."""
    with open(path, 'rb') as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise ValueError('%s: header pcap troncato' % path)
        magic = struct.unpack('<I', gh[:4])[0]
        if magic in (MAGIC_US, MAGIC_NS):
            endian, nano = '<', (magic == MAGIC_NS)
        else:
            magic = struct.unpack('>I', gh[:4])[0]
            if magic in (MAGIC_US, MAGIC_NS):
                endian, nano = '>', (magic == MAGIC_NS)
            else:
                raise ValueError('%s: non e\' un pcap classico' % path)
        linktype = struct.unpack(endian + 'I', gh[20:24])[0]
        rec = struct.Struct(endian + 'IIII')
        data = f.read()
    out = defaultdict(lambda: {'acc': [], 'deny': []})
    div = 1e9 if nano else 1e6
    off, n = 0, len(data)
    while off + 16 <= n:
        ts_sec, ts_frac, incl, _orig = rec.unpack_from(data, off)
        off += 16
        if off + incl > n:
            break
        res = parse_packet(data[off:off + incl], linktype, seq_off, seq_len, nets)
        off += incl
        if res is not None:
            net_id, seq, dport = res
            kind = 'deny' if dport in wildcard_ports else 'acc'
            out[net_id][kind].append((seq, ts_sec + ts_frac / div))
    for k in out:
        out[k]['acc'].sort(key=lambda x: x[1])
        out[k]['deny'].sort(key=lambda x: x[1])
    return out


# ----------------------------- pairing -------------------------------------
def pair_stream(tap, rx, max_delay_s, rx_offset_s):
    """tap, rx: liste (seq, ts) di UNA net. Ritorna lista (seq, t_tap, t_rx, delta).
    Per ogni seq: per ogni ricezione, prende la trasmissione 'ultima <= t_rx'."""
    tap_by_seq = defaultdict(list)
    for seq, ts in tap:
        tap_by_seq[seq].append(ts)
    rx_by_seq = defaultdict(list)
    for seq, ts in rx:
        rx_by_seq[seq].append(ts)
    pairs = []
    for seq, rxts in rx_by_seq.items():
        tts = tap_by_seq.get(seq)
        if not tts:
            continue
        tts = sorted(tts)
        rxts = sorted(rxts)
        used = [False] * len(tts)
        i = 0
        for tr in rxts:
            tr_adj = tr - rx_offset_s
            while i + 1 < len(tts) and tts[i + 1] <= tr_adj:
                i += 1
            if (not used[i]) and tts[i] <= tr_adj and (tr_adj - tts[i]) <= max_delay_s:
                pairs.append((seq, tts[i], tr, tr_adj - tts[i]))
                used[i] = True
    return pairs


# ----------------------------- ramp / steps --------------------------------
def parse_ramp(spec):
    """'20:1,10,100' -> (dur, [rates])."""
    dur_s, rates_s = spec.split(':', 1)
    dur = int(dur_s)
    rates = [int(x) for x in rates_s.split(',') if x != '']
    return dur, rates


def step_of(ts, t0, dur, n_steps):
    if dur <= 0 or n_steps <= 0:
        return 0
    s = int((ts - t0) // dur)
    return max(0, min(n_steps - 1, s))


def pct(sorted_vals, q):
    if not sorted_vals:
        return None
    idx = min(len(sorted_vals) - 1, int(q * (len(sorted_vals) - 1)))
    return sorted_vals[idx]


# ----------------------------- analisi -------------------------------------
def analyze(tap_by_net, rx_by_net, dur, rates, max_delay_s, rx_offset_s):
    n_steps = len(rates) if rates else 1
    # t0 = primo timestamp TAP in assoluto (allineamento relativo, robusto al
    # fatto che i timestamp HW non sono epoch reali).
    all_tap_ts = [ts for d in tap_by_net.values()
                  for lst in (d['acc'], d['deny']) for _s, ts in lst]
    t0 = min(all_tap_ts) if all_tap_ts else 0.0
    rows = []
    per_pkt = []
    empty = {'acc': [], 'deny': []}
    # accumulatori per la riga aggregata 'tot' (net=0): tutto il FW
    tot_acc_cnt = [0] * n_steps
    tot_deny_cnt = [0] * n_steps
    tot_leak_cnt = [0] * n_steps
    tot_matched = [0] * n_steps
    tot_deltas = [[] for _ in range(n_steps)]
    for net_id in sorted(set(list(tap_by_net.keys()) + list(rx_by_net.keys()))):
        tap = tap_by_net.get(net_id, empty)
        rx = rx_by_net.get(net_id, empty)
        # pairing SOLO sul traffico legittimo (le deny attese non arrivano all'RX)
        pairs = pair_stream(tap['acc'], rx['acc'], max_delay_s, rx_offset_s)
        # conteggi per step
        acc_cnt = [0] * n_steps    # TAP legittimi (denominatore della loss)
        deny_cnt = [0] * n_steps   # TAP attesi DENY (bloccati dal FW)
        leak_cnt = [0] * n_steps   # DENY visti all'RX (devono essere 0!)
        for _seq, ts in tap['acc']:
            acc_cnt[step_of(ts, t0, dur, n_steps)] += 1
        for _seq, ts in tap['deny']:
            deny_cnt[step_of(ts, t0, dur, n_steps)] += 1
        for _seq, ts in rx['deny']:
            leak_cnt[step_of(ts, t0, dur, n_steps)] += 1
        # deltas per step
        deltas = [[] for _ in range(n_steps)]
        matched = [0] * n_steps
        for seq, t_tap, t_rx, d in pairs:
            s = step_of(t_tap, t0, dur, n_steps)
            deltas[s].append(d)
            matched[s] += 1
            per_pkt.append((net_id, s, seq, '%.9f' % t_tap, '%.9f' % t_rx, '%.1f' % (d * 1e9)))
        for s in range(n_steps):
            tot_acc_cnt[s] += acc_cnt[s]
            tot_deny_cnt[s] += deny_cnt[s]
            tot_leak_cnt[s] += leak_cnt[s]
            tot_matched[s] += matched[s]
            tot_deltas[s].extend(deltas[s])
            ds = sorted(deltas[s])
            cnt = len(ds)
            mean = statistics.fmean(ds) if cnt else None
            std = statistics.pstdev(ds) if cnt > 1 else 0.0
            med = statistics.median(ds) if cnt else None
            p99 = pct(ds, 0.99)
            rate = rates[s] if rates else 0
            ta = acc_cnt[s]
            loss = ta - matched[s]
            loss_pct = (100.0 * loss / ta) if ta else 0.0
            rows.append({
                'net': net_id, 'step': s + 1, 'rate_pps': rate,
                'tap_acc': ta, 'deny_fw': deny_cnt[s],
                'rx_matched': matched[s], 'leak': leak_cnt[s],
                'loss': loss, 'loss_pct': round(loss_pct, 4),
                'delta_mean_ns': None if mean is None else round(mean * 1e9, 1),
                'delta_std_ns': round(std * 1e9, 1),
                'delta_median_ns': None if med is None else round(med * 1e9, 1),
                'delta_p99_ns': None if p99 is None else round(p99 * 1e9, 1),
            })
    # riga aggregata 'tot' (net=0): Delta dell'intero FW, media pesata sui
    # pacchetti appaiati di tutte le net (i deny non arrivano all'RX, quindi
    # il tot e' per costruzione sul solo traffico legittimo).
    for s in range(n_steps):
        ds = sorted(tot_deltas[s])
        cnt = len(ds)
        mean = statistics.fmean(ds) if cnt else None
        std = statistics.pstdev(ds) if cnt > 1 else 0.0
        med = statistics.median(ds) if cnt else None
        p99 = pct(ds, 0.99)
        rate = rates[s] if rates else 0
        ta = tot_acc_cnt[s]
        loss = ta - tot_matched[s]
        loss_pct = (100.0 * loss / ta) if ta else 0.0
        rows.append({
            'net': 0, 'step': s + 1, 'rate_pps': rate,
            'tap_acc': ta, 'deny_fw': tot_deny_cnt[s],
            'rx_matched': tot_matched[s], 'leak': tot_leak_cnt[s],
            'loss': loss, 'loss_pct': round(loss_pct, 4),
            'delta_mean_ns': None if mean is None else round(mean * 1e9, 1),
            'delta_std_ns': round(std * 1e9, 1),
            'delta_median_ns': None if med is None else round(med * 1e9, 1),
            'delta_p99_ns': None if p99 is None else round(p99 * 1e9, 1),
        })
    return rows, per_pkt


def write_csv(rows, path):
    import csv
    cols = ['net', 'step', 'rate_pps', 'tap_acc', 'deny_fw', 'rx_matched',
            'leak', 'loss', 'loss_pct', 'delta_mean_ns', 'delta_std_ns',
            'delta_median_ns', 'delta_p99_ns']
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_per_pkt(per_pkt, path):
    import csv
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['net', 'step', 'seq', 't_tap', 't_rx', 'delta_ns'])
        w.writerows(per_pkt)


# ----------------------------- grafici (riuso) -----------------------------
def make_plots(rows, tap_by_net, rx_by_net, dur, rates, max_delay_s,
               rx_offset_s, outdir, log_scale):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    os.makedirs(outdir, exist_ok=True)
    nets = sorted(set(r['net'] for r in rows))
    lbl = lambda n: 'tot' if n == 0 else 'net%d' % n

    # 1) Delta medio +/- std per step (vs rate)
    fig, ax = plt.subplots(figsize=(8, 5))
    for net_id in nets:
        rr = [r for r in rows if r['net'] == net_id and r['delta_mean_ns'] is not None]
        if not rr:
            continue
        x = [r['rate_pps'] for r in rr]
        y = [r['delta_mean_ns'] for r in rr]
        e = [r['delta_std_ns'] for r in rr]
        ax.errorbar(x, y, yerr=e, marker='o', capsize=3, label=lbl(net_id))
    if log_scale:
        ax.set_xscale('log')
    ax.set_xlabel('rate per step (pps, TOTALE)')
    ax.set_ylabel('Delta = t_rx - t_tap  (ns)')
    ax.set_title('Ritardo FW TAP->RX per step')
    ax.grid(True, which='both', alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, 'delta_vs_step.png'), dpi=130)
    plt.close(fig)

    # 2) Loss reale % e deny attese % per step
    fig, ax = plt.subplots(figsize=(8, 5))
    for net_id in nets:
        rr = [r for r in rows if r['net'] == net_id]
        x = [r['rate_pps'] for r in rr]
        y = [r['loss_pct'] for r in rr]
        ax.plot(x, y, marker='s', label=lbl(net_id) + ' loss reale')
        tot = [r['tap_acc'] + r['deny_fw'] for r in rr]
        yd = [100.0 * r['deny_fw'] / t if t else 0.0 for r, t in zip(rr, tot)]
        ax.plot(x, yd, marker='v', linestyle='--', label=lbl(net_id) + ' deny attese')
    if log_scale:
        ax.set_xscale('log')
    ax.set_xlabel('rate per step (pps, TOTALE)')
    ax.set_ylabel('loss reale / deny attese (%)')
    ax.set_title('Perdita TAP->RX per step')
    ax.grid(True, which='both', alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, 'loss_vs_step.png'), dpi=130)
    plt.close(fig)

    # 3) Throughput in (TAP) vs out (RX matched) per step
    fig, ax = plt.subplots(figsize=(8, 5))
    for net_id in nets:
        rr = [r for r in rows if r['net'] == net_id]
        x = [r['rate_pps'] for r in rr]
        yin = [r['tap_acc'] / dur if dur else r['tap_acc'] for r in rr]
        yout = [r['rx_matched'] / dur if dur else r['rx_matched'] for r in rr]
        ax.plot(x, yin, marker='o', linestyle='--', label=lbl(net_id) + ' in (TAP)')
        ax.plot(x, yout, marker='x', label=lbl(net_id) + ' out (RX)')
    if log_scale:
        ax.set_xscale('log')
        ax.set_yscale('log')
    ax.set_xlabel('rate per step (pps, TOTALE)')
    ax.set_ylabel('throughput (pps)')
    ax.set_title('Throughput I/O per step')
    ax.grid(True, which='both', alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, 'throughput_vs_step.png'), dpi=130)
    plt.close(fig)

    # 4) CDF del Delta (tutti gli step)
    fig, ax = plt.subplots(figsize=(8, 5))
    empty = {'acc': [], 'deny': []}
    for net_id in nets:
        pairs = pair_stream(tap_by_net.get(net_id, empty)['acc'],
                            rx_by_net.get(net_id, empty)['acc'],
                            max_delay_s, rx_offset_s)
        ds = sorted(d * 1e9 for _s, _tt, _tr, d in pairs)
        if not ds:
            continue
        ys = [(i + 1) / len(ds) for i in range(len(ds))]
        ax.plot(ds, ys, label=lbl(net_id))
    ax.set_xlabel('Delta (ns)')
    ax.set_ylabel('CDF')
    ax.set_title('CDF del ritardo TAP->RX')
    ax.grid(True, alpha=0.3)
    ax.legend(loc='lower right')
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, 'delta_cdf.png'), dpi=130)
    plt.close(fig)


# ----------------------------- selftest ------------------------------------
def _write_min_pcap(path, records, linktype=101, nano=True):
    """records: lista di (ts_float, raw_bytes). Scrive un pcap classico minimale."""
    magic = MAGIC_NS if nano else MAGIC_US
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', magic, 2, 4, 0, 0, 65535, linktype))
        div = 1e9 if nano else 1e6
        for ts, raw in records:
            sec = int(ts)
            frac = int(round((ts - sec) * div))
            f.write(struct.pack('<IIII', sec, frac, len(raw), len(raw)))
            f.write(raw)


def _mk_udp_ip(dst, seq, sport=1234, dport=5000, payload_len=4):
    """Costruisce un IP+UDP RAW con seq nei primi 4 byte del payload (BE)."""
    src = bytes([10, 0, 0, 1])
    dstb = bytes(int(x) for x in dst.split('.'))
    pl = seq.to_bytes(4, 'big') + b'\x00' * max(0, payload_len - 4)
    udp = struct.pack('>HHHH', sport, dport, 8 + len(pl), 0) + pl
    tot = 20 + len(udp)
    iph = struct.pack('>BBHHHBBH', 0x45, 0, tot, 0, 0, 64, 17, 0) + src + dstb
    return iph + udp


def selftest():
    import tempfile
    tmp = tempfile.mkdtemp(prefix='credial_')
    tap_path = os.path.join(tmp, 'tap.pcap')
    rx_path = os.path.join(tmp, 'rx.pcap')
    # 100 seq distinti, 3 giri (wrap) -> seq si ripete; due net.
    # 1 pacchetto ogni 10 e' una DENY attesa (porta wildcard 6666): il "FW"
    # li blocca -> non compaiono all'RX, ma NON sono loss. In piu' si inietta
    # 1 leak (una DENY che arriva all'RX): deve essere rilevato.
    N, WRAPS = 100, 3
    ACC_PORT, WILD_PORT = 5000, 6666
    delay = 5e-6          # 5 us
    tap_recs, rx_recs = [], []
    t = 1000.0
    lost = denied = 0
    k = 0
    leak_rec = None
    for w in range(WRAPS):
        for seq in range(N):
            for net, dst in ((1, '10.0.1.50'), (2, '10.0.2.50')):
                wild = (seq % 10 == 3)
                raw = _mk_udp_ip(dst, seq, dport=WILD_PORT if wild else ACC_PORT)
                tap_recs.append((t, raw))
                if wild:
                    denied += 1
                    if leak_rec is None and w == 1:
                        leak_rec = (t + delay, raw)      # il leak iniettato
                elif k % 50 == 7:
                    lost += 1                            # perdita reale
                else:
                    rx_recs.append((t + delay, raw))
                k += 1
                t += 1e-4   # 100 us tra pacchetti (wrap-period >> delay)
    rx_recs.append(leak_rec)
    rx_recs.sort(key=lambda r: r[0])
    _write_min_pcap(tap_path, tap_recs)
    _write_min_pcap(rx_path, rx_recs)

    nets = [(1, ipaddress.ip_network('10.0.1.0/24')),
            (2, ipaddress.ip_network('10.0.2.0/24'))]
    wild_ports = {WILD_PORT}
    tap_by_net = read_pcap(tap_path, 0, 4, nets, wild_ports)
    rx_by_net = read_pcap(rx_path, 0, 4, nets, wild_ports)

    tot_acc = sum(len(v['acc']) for v in tap_by_net.values())
    tot_deny = sum(len(v['deny']) for v in tap_by_net.values())
    assert tot_acc + tot_deny == N * WRAPS * 2, (tot_acc, tot_deny)
    assert tot_deny == denied, (tot_deny, denied)

    ok = True
    matched_total = 0
    for net_id, _ in nets:
        pairs = pair_stream(tap_by_net[net_id]['acc'], rx_by_net[net_id]['acc'],
                            1e-3, 0.0)
        matched_total += len(pairs)
        for _seq, _tt, _tr, d in pairs:
            if abs(d - delay) > 1e-9:
                ok = False
    # tutti i legittimi ricevuti devono essere appaiati correttamente
    assert matched_total == tot_acc - lost, (matched_total, tot_acc - lost)
    assert ok, 'delta non corrisponde al ritardo iniettato'

    rows, _per_pkt = analyze(tap_by_net, rx_by_net, dur=1, rates=[1],
                             max_delay_s=1e-3, rx_offset_s=0.0)
    per_net_rows = [r for r in rows if r['net'] != 0]
    agg_rows = [r for r in rows if r['net'] == 0]
    tot_loss = sum(r['loss'] for r in per_net_rows)
    tot_leak = sum(r['leak'] for r in per_net_rows)
    tot_deny_rows = sum(r['deny_fw'] for r in per_net_rows)
    # la riga 'tot' deve coincidere con la somma delle righe per-net
    assert agg_rows and agg_rows[0]['tap_acc'] == tot_acc, agg_rows
    assert agg_rows[0]['loss'] == tot_loss and agg_rows[0]['deny_fw'] == tot_deny_rows
    assert tot_loss == lost, (tot_loss, lost)
    assert tot_deny_rows == denied, (tot_deny_rows, denied)
    assert tot_leak == 1, tot_leak
    print('[selftest] OK  acc=%d deny=%d matched=%d loss=%d leak=%d  delta=%.0fns'
          % (tot_acc, tot_deny, matched_total, lost, tot_leak, delay * 1e9))
    return 0


# ----------------------------- main ----------------------------------------
def main():
    ap = argparse.ArgumentParser(description='Differenza timestamp TAP<->RX (REDIAL/sendpkts).')
    ap.add_argument('--tap', help='pcap del TAP')
    ap.add_argument('--rx', help='pcap del RX')
    ap.add_argument('--ramp', help='spec rampa DUR:R1,...,RN (per stat per-step)')
    ap.add_argument('--net1-cidr', default='10.0.1.0/24')
    ap.add_argument('--net2-cidr', default='10.0.2.0/24')
    ap.add_argument('--seq-offset', type=int, default=0, help='offset del seq nel payload (byte)')
    ap.add_argument('--seq-len', type=int, default=4, help='lunghezza del seq (byte, BE)')
    ap.add_argument('--rx-offset-ns', type=float, default=0.0,
                    help='offset di clock RX da sottrarre (calibrazione, vedi measure_offset)')
    ap.add_argument('--max-delay-ms', type=float, default=200.0,
                    help='finestra massima di accoppiamento (deve restare < periodo di wrap)')
    ap.add_argument('--csv', help='output CSV per-step')
    ap.add_argument('--per-packet-csv', help='output CSV per-pacchetto (opzionale)')
    ap.add_argument('--plot', help='cartella di output per i grafici')
    ap.add_argument('--log-scale', action='store_true', help='asse x (rate) in scala log')
    ap.add_argument('--rules', help='fw1.rules: dport wildcard -> DENY attese (escluse dalla loss)')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.tap or not args.rx:
        ap.error('--tap e --rx sono obbligatori (oppure usa --selftest)')

    nets = [(1, ipaddress.ip_network(args.net1_cidr)),
            (2, ipaddress.ip_network(args.net2_cidr))]
    dur, rates = (0, [])
    if args.ramp:
        dur, rates = parse_ramp(args.ramp)

    wild = load_wildcard_ports(args.rules) if args.rules else set()
    if args.rules:
        print('[rules] %d porte wildcard (DENY attese) da %s' % (len(wild), args.rules))
    tap_by_net = read_pcap(args.tap, args.seq_offset, args.seq_len, nets, wild)
    rx_by_net = read_pcap(args.rx, args.seq_offset, args.seq_len, nets, wild)

    max_delay_s = args.max_delay_ms / 1e3
    rx_offset_s = args.rx_offset_ns / 1e9
    rows, per_pkt = analyze(tap_by_net, rx_by_net, dur, rates, max_delay_s, rx_offset_s)

    # stampa tabellare
    hdr = ('net', 'step', 'rate', 'tap_acc', 'deny', 'rx', 'loss', 'loss%',
           'leak', 'mean(ns)', 'std(ns)', 'med(ns)', 'p99(ns)')
    print('%-3s %-4s %-8s %-9s %-8s %-9s %-8s %-7s %-5s %-10s %-9s %-9s %-9s' % hdr)
    for r in rows:
        print('%-3s %-4d %-8d %-9d %-8d %-9d %-8d %-7.3f %-5d %-10s %-9s %-9s %-9s' % (
            'tot' if r['net'] == 0 else r['net'], r['step'], r['rate_pps'], r['tap_acc'], r['deny_fw'],
            r['rx_matched'], r['loss'], r['loss_pct'], r['leak'],
            r['delta_mean_ns'], r['delta_std_ns'],
            r['delta_median_ns'], r['delta_p99_ns']))
    tot_leak = sum(r['leak'] for r in rows)
    if tot_leak:
        print("[WARN] %d pacchetti DENY attesi visti all'RX (leak)!" % tot_leak)

    if args.csv:
        write_csv(rows, args.csv)
        print('[csv] ', args.csv)
    if args.per_packet_csv:
        write_per_pkt(per_pkt, args.per_packet_csv)
        print('[csv] ', args.per_packet_csv)
    if args.plot:
        make_plots(rows, tap_by_net, rx_by_net, dur if dur else 1, rates,
                   max_delay_s, rx_offset_s, args.plot, args.log_scale)
        print('[plot]', args.plot)
    return 0


if __name__ == '__main__':
    sys.exit(main())
