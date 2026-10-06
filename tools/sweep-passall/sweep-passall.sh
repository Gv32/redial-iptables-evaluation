#!/usr/bin/env bash
# sweep-passall.sh v3 (--no-pkt) — test pass-all con RUN SEPARATE: per ogni ruleset in
# rules_sweep/ carica il FW via ssh e, per ogni replica e per ogni rate, esegue
# una run indipendente (cattura + udpramp a rate fisso) con una pausa di
# silenzio tra le run. Sigma = h verificato dai contatori A OGNI RUN.
# Le run gia' analizzate (delta.csv presente) vengono saltate: si puo'
# interrompere e rilanciare. Derivato da campagna-redial.sh + run-experiment.sh.
# Uso:  sudo -v && ./sweep-passall.sh --tag sweep-prof [--offset -13045] [--reps 2] [--silence 5]
set -euo pipefail

TAG="sweep-prof"; DUR=20; RATES="100000,200000,400000,800000"
REPS=2; SILENCE=5; NOPKT=0
RULES_DIR="rules_sweep"; OFFSET=0
FW_HOST="drago@192.168.100.103"
PROBE_DST="10.0.1.50"; PROBE_PORT=5000
KNEE_M=115; KEEP_PCAP=0
GRACE_BEFORE=2; GRACE_AFTER=4

while [ $# -gt 0 ]; do case "$1" in
  --tag) TAG="$2"; shift 2;;
  --dur) DUR="$2"; shift 2;;
  --rates) RATES="$2"; shift 2;;
  --reps) REPS="$2"; shift 2;;
  --silence) SILENCE="$2"; shift 2;;
  --no-pkt) NOPKT=1; shift;;
  --rules-dir) RULES_DIR="$2"; shift 2;;
  --offset) OFFSET="$2"; shift 2;;
  --keep-pcap) KEEP_PCAP=1; shift;;
  *) echo "[ERR] flag sconosciuto: $1"; exit 1;;
esac; done

[ "$(id -u)" -ne 0 ] || { echo "[ERR] da utente normale: sudo -v && ./sweep-passall.sh"; exit 1; }
ls "$RULES_DIR"/sweep_h*.rules >/dev/null 2>&1 || { echo "[ERR] nessun ruleset in $RULES_DIR/ (lancia gen_sweep_rules.py)"; exit 1; }

# file di appoggio di listen.sh: se restano di root (run passate col sudo) le run muoiono
sudo rm -f /tmp/et_pre_tap.txt /tmp/et_pre_rx.txt /tmp/et_post_tap.txt \
           /tmp/et_post_rx.txt /tmp/tcpdump_tap.log /tmp/tcpdump_rx.log

LISTEN_SEC=$(( DUR + GRACE_BEFORE + GRACE_AFTER ))
BASE="campagne/${TAG}"
mkdir -p "$BASE" captures; chmod 1777 captures 2>/dev/null || true

avail_gb=$(df -BG --output=avail . | tail -1 | tr -dc '0-9')
[ "$avail_gb" -ge 15 ] || { echo "[ERR] servono ~15 GB liberi (disponibili ${avail_gb}G)"; exit 1; }

newest_ts() { ls -t captures/tap_*.pcap | head -1 | sed 's#.*tap_\(.*\)\.pcap#\1#'; }

echo "[i] tag=$TAG  dur=${DUR}s/run  rates=$RATES  reps=$REPS  silenzio=${SILENCE}s  offset=${OFFSET}ns"
echo "[i] promemoria: timer silenziati su entrambi gli host? Solo di giorno!"

for RULES in "$RULES_DIR"/sweep_h*.rules; do
  H=$(basename "$RULES" | sed 's/sweep_h0*\([0-9]\+\)\.rules/\1/')
  HDIR="$BASE/h$(printf '%04d' "$H")"; mkdir -p "$HDIR"
  echo; echo "======== h=$H ========"

  # 1) carica il ruleset sul FW + verifica numero regole e posizione pass-all
  scp -q "$RULES" "$FW_HOST:/tmp/sweep.rules"
  ssh "$FW_HOST" 'sudo ip netns exec FW iptables-restore < /tmp/sweep.rules'
  N=$(ssh "$FW_HOST" 'sudo ip netns exec FW iptables -S FORWARD | grep -c "^-A"')
  P=$(ssh "$FW_HOST" 'sudo ip netns exec FW iptables -S FORWARD' | grep -v '^-P' | grep -n 'SWEEP:passall' | cut -d: -f1)
  [ "$N" = 1001 ] || { echo "[ERR] $N regole sul FW (attese 1001)"; exit 1; }
  [ "$P" = "$H" ] || { echo "[ERR] pass-all in posizione '$P' (attesa $H)"; exit 1; }
  echo "[OK]   1001 regole, pass-all in posizione $H"

  for REP in $(seq 1 "$REPS"); do
    for R in ${RATES//,/ }; do
      DST="$HDIR/r${R}_rep${REP}"; mkdir -p "$DST"
      [ -s "$DST/delta.csv" ] && { echo "[skip] h=$H rate=$R rep=$REP gia' fatto"; continue; }
      M=$(( R * H / 1000000 ))
      SAT=""; [ "$M" -gt "$KNEE_M" ] && SAT="  (SATURO atteso: ${M}M val/s > ~${KNEE_M}M, fuori fit)"
      echo "---- h=$H  rate=$R pps  rep=$REP/$REPS$SAT"

      # contatori a zero PER RUN: il check sigma e' esatto run per run
      ssh "$FW_HOST" 'sudo ip netns exec FW iptables -Z FORWARD'

      # cattura + probe (listen.sh e udpramp originali, non modificati)
      ./listen.sh "$LISTEN_SEC" "$PROBE_PORT" captures & LPID=$!
      sleep "$GRACE_BEFORE"
      sudo ip netns exec SX ./udpramp --src-ip 10.0.0.1 --dst-ip "$PROBE_DST" \
          --src-port "$PROBE_PORT" --dst-port "$PROBE_PORT" \
          --payload 4 --cpu 2 --ramp "${DUR}:${R}" 2>&1 | tee "$DST/udpramp.log"
      wait "$LPID" || true
      TS=$(newest_ts)
      sudo mv "captures/tap_${TS}.pcap" "captures/rx_${TS}.pcap" "$DST/"
      sudo chown -R "$USER": "$DST"

      # sigma = h dai contatori di QUESTA run
      SENT=$(awk -F: '/totale sent/{gsub(/ /,"",$2); print $2}' "$DST/udpramp.log")
      ssh "$FW_HOST" 'sudo ip netns exec FW iptables -nvL FORWARD -x' > "$DST/counters.txt"
      awk -v h="$H" -v sent="$SENT" '
        NR>2 { i++; if ($1+0 > 0) hits[i]=$1 }
        END {
          bad=0
          for (p in hits) if (p+0 != h+0) { printf "[ERR] contatore inatteso a pos %s: %d pkt\n", p, hits[p]; bad=1 }
          if (!(h in hits))              { printf "[ERR] pass-all a pos %d: 0 pkt!\n", h; bad=1 }
          else if (hits[h]+0 != sent+0)    printf "[WARN] pass-all %d pkt vs %d inviati (persi prima del FW: %d)\n", hits[h], sent, sent-hits[h]
          if (!bad) printf "[OK] sigma = h = %d (pass-all: %d pkt, filler tutti a 0)\n", h, hits[h]
        }' "$DST/counters.txt" | tee "$DST/sigma_check.txt"

      # tempi (compare-redial originale) + pulizia pcap
      # --no-pkt: niente per-packet csv (campagne solo-medie, es. rate fine)
      PKTARGS=""
      [ "$NOPKT" = 1 ] || PKTARGS="--per-packet-csv $DST/delta_pkt.csv"
      ./compare-redial.py --tap "$DST/tap_${TS}.pcap" --rx "$DST/rx_${TS}.pcap" \
          --ramp "${DUR}:${R}" --rx-offset-ns "$OFFSET" \
          --csv "$DST/delta.csv" $PKTARGS | tee "$DST/delta.txt"
      [ "$NOPKT" = 1 ] || gzip -f "$DST/delta_pkt.csv"
      [ "$KEEP_PCAP" = 1 ] || sudo rm -f "$DST/tap_${TS}.pcap" "$DST/rx_${TS}.pcap"

      # silenzio tra una run e l'altra
      sleep "$SILENCE"
    done
  done
done

# summary unico: una riga per (h, rate, rep) dalla riga 'tot' (net=0) dei csv
SUM="$BASE/sweep_summary.csv"
echo "h,rate_pps,rep,mean_ns,std_ns,median_ns,p99_ns,loss" > "$SUM"
for d in "$BASE"/h*/r*_rep*/delta.csv; do
  hh=$(basename "$(dirname "$(dirname "$d")")" | sed 's/^h0*//')
  rr=$(basename "$(dirname "$d")" | sed 's/^r\([0-9]*\)_rep.*/\1/')
  pp=$(basename "$(dirname "$d")" | sed 's/.*_rep//')
  awk -F, -v h="$hh" -v r="$rr" -v p="$pp" '{ gsub(/\r/,"") } NR>1 && $1==0 {print h","r","p","$10","$11","$12","$13","$8}' "$d" >> "$SUM"
done
echo; echo "[done] sweep completato → $SUM   (grafici: python3 plot-sweep.py $BASE)"
