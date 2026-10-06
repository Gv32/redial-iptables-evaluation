#!/usr/bin/env python3
# compare-redial-win.py - Delta TAP<->RX con statistiche A FINESTRE.
# ----------------------------------------------------------------------------
# PERCHE': il disturbo diurno e' un transitorio di pochi secondi che gonfia
# std e p99 dell'intera run lasciando la media quasi intatta. Si spezza la
# run in finestre da --win secondi (default 5 -> 12 su 60 s) e si riporta:
#   * mediana delle MEDIE di finestra  -> D robusto della run
#   * mediana delle STD di finestra    -> dispersione vera
#   * conteggio finestre sporche (std > soglia): <= 25% -> run utilizzabile
# NON tocca compare-redial.py: lo importa e ne riusa parser pcap, pairing,
# rampa e ruleset (gia' validati dal suo selftest).
#
# Uso tipico (run singola 60 s a 400k, criterio POST):
#   ./compare-redial-win.py --tap captures/tap_X.pcap --rx captures/rx_X.pcap \
#       --ramp 60:400000 --rx-offset-ns -11973 --rules fw17525.rules \
#       --std-warn-us 25 --csv win.csv
#
# Selftest (sintetico: 20 finestre, disturbo iniettato in 2):
#   ./compare-redial-win.py --selftest

import argparse
import importlib.util
import ipaddress
import os
import statistics
import sys


def load_base():
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, 'compare-redial.py')
    if not os.path.exists(path):
        sys.exit('[ERRORE] compare-redial.py non trovato accanto a questo script')
    spec = importlib.util.spec_from_file_location('compare_redial', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def window_stats(deltas_by_win, std_warn_ns):
    """deltas_by_win: lista di liste (una per finestra) di delta in secondi.
    Ritorna (righe per finestra, riassunto) per UNA coppia (net, step)."""
    rows, means, stds, all_ds = [], [], [], []
    for w, ds in enumerate(deltas_by_win):
        ds = sorted(ds)
        cnt = len(ds)
        if cnt == 0:
            rows.append({'win': w + 1, 'count': 0, 'mean_ns': None,
                         'std_ns': None, 'med_ns': None, 'p99_ns': None,
                         'flag': ''})
            continue
        mean = statistics.fmean(ds) * 1e9
        std = (statistics.pstdev(ds) if cnt > 1 else 0.0) * 1e9
        med = statistics.median(ds) * 1e9
        p99 = ds[min(cnt - 1, int(0.99 * (cnt - 1)))] * 1e9
        rows.append({'win': w + 1, 'count': cnt, 'mean_ns': round(mean, 1),
                     'std_ns': round(std, 1), 'med_ns': round(med, 1),
                     'p99_ns': round(p99, 1), 'flag': ''})
        means.append(mean)
        stds.append(std)
        all_ds.extend(ds)
    if not means:
        return rows, None
    soglia = std_warn_ns if std_warn_ns else 2.0 * statistics.median(stds)
    soglia = max(soglia, 25000.0)  # pavimento 25 us: sotto c'e' il rumore di
    #   fondo delle finestre pulite (18-24 us nei POST), non il disturbo
    dirty = 0
    for r in rows:
        if r['count'] and r['std_ns'] > soglia:
            r['flag'] = 'SPORCA'
            dirty += 1
    summary = {'n_win': len(means),
               'med_mean_ns': round(statistics.median(means), 1),
               'med_std_ns': round(statistics.median(stds), 1),
               'glob_mean_ns': round(statistics.fmean(all_ds) * 1e9, 1),
               'glob_std_ns': round(statistics.pstdev(all_ds) * 1e9, 1)
               if len(all_ds) > 1 else 0.0,
               'dirty': dirty, 'soglia_ns': round(soglia, 1)}
    return rows, summary


def analyze_windows(cr, tap_by_net, rx_by_net, dur, rates, win_dur,
                    max_delay_s, rx_offset_s, std_warn_ns):
    n_steps = len(rates) if rates else 1
    all_tap_ts = [ts for d in tap_by_net.values()
                  for lst in (d['acc'], d['deny']) for _s, ts in lst]
    t0 = min(all_tap_ts) if all_tap_ts else 0.0
    if dur <= 0:
        dur = (max(all_tap_ts) - t0) if all_tap_ts else 1.0
    n_win = max(1, int(round(dur / win_dur)))
    empty = {'acc': [], 'deny': []}
    net_ids = sorted(set(list(tap_by_net.keys()) + list(rx_by_net.keys())))
    buckets = {n: [[[] for _ in range(n_win)] for _ in range(n_steps)]
               for n in net_ids + [0]}
    for net_id in net_ids:
        pairs = cr.pair_stream(tap_by_net.get(net_id, empty)['acc'],
                               rx_by_net.get(net_id, empty)['acc'],
                               max_delay_s, rx_offset_s)
        for _seq, t_tap, _t_rx, d in pairs:
            s = cr.step_of(t_tap, t0, dur, n_steps)
            w = int((t_tap - t0 - s * dur) // win_dur)
            w = max(0, min(n_win - 1, w))
            buckets[net_id][s][w].append(d)
            buckets[0][s][w].append(d)
    results = []
    for net_id in net_ids + [0]:
        for s in range(n_steps):
            rows, summary = window_stats(buckets[net_id][s], std_warn_ns)
            results.append((net_id, s + 1, rows, summary))
    return results, n_win


def print_results(results, win_dur):
    lbl = lambda n: 'tot' if n == 0 else 'net%d' % n
    hdr = ('net', 'step', 'win', 't(s)', 'count', 'mean(ns)', 'std(ns)',
           'med(ns)', 'p99(ns)', 'flag')
    print('%-4s %-4s %-4s %-6s %-9s %-10s %-10s %-10s %-10s %s' % hdr)
    for net_id, step, rows, _summary in results:
        for r in rows:
            print('%-4s %-4d %-4d %-6.1f %-9d %-10s %-10s %-10s %-10s %s' % (
                lbl(net_id), step, r['win'], (r['win'] - 1) * win_dur,
                r['count'], r['mean_ns'], r['std_ns'], r['med_ns'],
                r['p99_ns'], r['flag']))
    print()
    for net_id, step, _rows, s in results:
        if s is None:
            continue
        print('[win] %s step %d: mediana-finestre mean=%s ns  std=%s ns | '
              'globale mean=%s ns std=%s ns | finestre sporche %d/%d '
              '(soglia std %s ns)'
              % (lbl(net_id), step, s['med_mean_ns'], s['med_std_ns'],
                 s['glob_mean_ns'], s['glob_std_ns'], s['dirty'],
                 s['n_win'], s['soglia_ns']))
        if net_id == 0:
            if s['dirty'] * 4 <= s['n_win']:
                print('[OK]   run utilizzabile: D = mediana delle medie di '
                      'finestra (%s ns), dispersione = mediana delle std (%s ns)'
                      % (s['med_mean_ns'], s['med_std_ns']))
            else:
                print('[WARN] disturbo su piu\' del 25%% delle finestre '
                      '(%d/%d) - run da ripetere' % (s['dirty'], s['n_win']))


def write_win_csv(results, path, rates, win_dur):
    import csv
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['net', 'step', 'rate_pps', 'win', 't_start_s', 'count',
                    'mean_ns', 'std_ns', 'med_ns', 'p99_ns', 'flag'])
        for net_id, step, rows, _summary in results:
            rate = rates[step - 1] if rates else 0
            for r in rows:
                w.writerow([net_id, step, rate, r['win'],
                            round((r['win'] - 1) * win_dur, 1), r['count'],
                            r['mean_ns'], r['std_ns'], r['med_ns'],
                            r['p99_ns'], r['flag']])


def selftest():
    """20 s sintetici a 100 pkt/s per net, Delta 5,2 us medi con jitter piccolo;
    nelle finestre 9-10 si inietta un disturbo (jitter enorme). Attesi:
    mediana-finestre ~5200 ns, media globale gonfiata, sporche = 2/20."""
    cr = load_base()
    import tempfile
    tmp = tempfile.mkdtemp(prefix='crwin_')
    tap_path = os.path.join(tmp, 'tap.pcap')
    rx_path = os.path.join(tmp, 'rx.pcap')
    tap_recs, rx_recs = [], []
    t0, k = 1000.0, 0
    for i in range(2000):                       # 100 pps x 20 s
        t = t0 + i * 0.01
        dirty = 8.0 <= (t - t0) < 10.0          # finestre 9 e 10
        for dst in ('10.0.1.50', '10.0.2.50'):
            raw = cr._mk_udp_ip(dst, k)
            tap_recs.append((t, raw))
            jit = (i % 5) * (50e-6 if dirty else 1e-7)
            rx_recs.append((t + 5e-6 + jit, raw))
            k += 1
    cr._write_min_pcap(tap_path, tap_recs)
    cr._write_min_pcap(rx_path, rx_recs)
    nets = [(1, ipaddress.ip_network('10.0.1.0/24')),
            (2, ipaddress.ip_network('10.0.2.0/24'))]
    tap_by_net = cr.read_pcap(tap_path, 0, 4, nets, set())
    rx_by_net = cr.read_pcap(rx_path, 0, 4, nets, set())
    results, n_win = analyze_windows(cr, tap_by_net, rx_by_net, 20, [200],
                                     1.0, 1e-3, 0.0, None)
    s = [r[3] for r in results if r[0] == 0][0]
    assert n_win == 20, n_win
    assert abs(s['med_mean_ns'] - 5200.0) < 5.0, s      # mediana insensibile
    assert s['glob_mean_ns'] > 10000.0, s               # media globale gonfiata
    assert s['dirty'] == 2, s                           # 2 finestre flaggate
    print('[selftest] OK  mediana-finestre=%.1f ns (atteso ~5200)  '
          'globale=%.1f ns (gonfiata dal disturbo)  sporche=%d/20'
          % (s['med_mean_ns'], s['glob_mean_ns'], s['dirty']))
    return 0


def main():
    ap = argparse.ArgumentParser(
        description='Delta TAP<->RX con statistiche a finestre (REDIAL).')
    ap.add_argument('--tap', help='pcap del TAP')
    ap.add_argument('--rx', help='pcap del RX')
    ap.add_argument('--ramp', help='spec rampa DUR:R1,...,RN (come compare-redial.py)')
    ap.add_argument('--win', type=float, default=5.0,
                    help='durata finestra in secondi (default 5)')
    ap.add_argument('--net1-cidr', default='10.0.1.0/24')
    ap.add_argument('--net2-cidr', default='10.0.2.0/24')
    ap.add_argument('--seq-offset', type=int, default=0)
    ap.add_argument('--seq-len', type=int, default=4)
    ap.add_argument('--rx-offset-ns', type=float, default=0.0)
    ap.add_argument('--max-delay-ms', type=float, default=200.0)
    ap.add_argument('--rules', help='fw.rules: dport wildcard -> DENY attese')
    ap.add_argument('--std-warn-us', type=float, default=None,
                    help='soglia std per finestra sporca in us (40 PRE / 25 POST); '
                         'default: 2x la mediana delle std di finestra; '
                         'pavimento 25 us in ogni caso')
    ap.add_argument('--csv', help='CSV con una riga per finestra')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.tap or not args.rx:
        ap.error('--tap e --rx sono obbligatori (oppure usa --selftest)')

    cr = load_base()
    nets = [(1, ipaddress.ip_network(args.net1_cidr)),
            (2, ipaddress.ip_network(args.net2_cidr))]
    dur, rates = (0, [])
    if args.ramp:
        dur, rates = cr.parse_ramp(args.ramp)
    wild = cr.load_wildcard_ports(args.rules) if args.rules else set()
    if args.rules:
        print('[rules] %d porte wildcard (DENY attese) da %s'
              % (len(wild), args.rules))
    tap_by_net = cr.read_pcap(args.tap, args.seq_offset, args.seq_len, nets, wild)
    rx_by_net = cr.read_pcap(args.rx, args.seq_offset, args.seq_len, nets, wild)
    std_warn_ns = args.std_warn_us * 1000.0 if args.std_warn_us else None
    results, _n_win = analyze_windows(cr, tap_by_net, rx_by_net, dur, rates,
                                      args.win, args.max_delay_ms / 1e3,
                                      args.rx_offset_ns / 1e9, std_warn_ns)
    print_results(results, args.win)
    if args.csv:
        write_win_csv(results, args.csv, rates, args.win)
        print('[csv] ', args.csv)
    return 0


if __name__ == '__main__':
    sys.exit(main())
