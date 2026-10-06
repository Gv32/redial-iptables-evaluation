#!/usr/bin/env bash
# campagna-redial.sh — per un ruleset caricato sul FW esegue TUTTE E TRE le
# coppie rho (0.25/0.5/0.75): 3 run PRE, pausa REDIAL, 3 run POST.
# Ogni run in campagne/<tag>/rho<r>/{pre,post}/ con pcap, epoch, sigma json,
# delta.csv/.txt. Prerequisiti: ruleset PRE sul FW + vettori rigenerati
# (gen_packets_v2.py -r <rules> --count 10000 --seed 42).
set -euo pipefail

TAG=""; RATE=400000; RULES="fw1.rules"; OFFSET=-11973
PRE_N=601; POST_N=""; STD_PRE=40; STD_POST=20; KNEE_M=130; MAX_RETRY=3

while [ $# -gt 0 ]; do
  case "$1" in
    --tag)        TAG="$2"; shift 2;;
    --rate)       RATE="$2"; shift 2;;
    --rules)      RULES="$2"; shift 2;;
    --pre-rules)  PRE_N="$2"; shift 2;;
    --post-rules) POST_N="$2"; shift 2;;
    --offset)     OFFSET="$2"; shift 2;;
    *) echo "[ERR] flag sconosciuto: $1"; exit 1;;
  esac
done
[ -n "$TAG" ]   || { echo "[ERR] serve --tag"; exit 1; }
[ -f "$RULES" ] || { echo "[ERR] manca il file regole: $RULES"; exit 1; }

RAMP="60:${RATE}"
BASE="campagne/${TAG}"
RHOS="0.25 0.5 0.75"

# MAI lanciare lo script con sudo: il collector farebbe ssh come root@FW
if [ "$(id -u)" -eq 0 ]; then echo "[ERR] lancialo da utente normale: il sudo serve solo all'interno"; exit 1; fi

mkdir -p "$BASE"
# captures/ deve essere scrivibile sia da tcpdump (crea i pcap) sia da noi (mv)
mkdir -p captures; chmod 1777 captures 2>/dev/null || true
[ -w captures ] || { echo "[ERR] captures/ non scrivibile: sudo chown $USER: captures && chmod 1777 captures"; exit 1; }

# ~3,4 GB di pcap a run x 6 run: controlla lo spazio prima di partire
avail_gb=$(df -BG --output=avail . | tail -1 | tr -dc '0-9')
[ "$avail_gb" -ge 25 ] || { echo "[ERR] servono ~25 GB liberi (disponibili ${avail_gb}G)"; exit 1; }

split_of() { case "$1" in 0.25) echo 75,25;; 0.5) echo 50,50;; 0.75) echo 25,75;; esac; }
dir_of()   { printf '%s/rho%s' "$BASE" "${1/./}"; }
newest_ts() { ls -t captures/tap_*.pcap | head -1 | sed 's#.*tap_\(.*\)\.pcap#\1#'; }

check_zero() {  # $1 = regole attese (vuoto = solo azzera)
  local out n
  out=$(python3 sigma_collector_subnet.py zero)
  echo "$out"
  n=$(echo "$out" | grep -o '[0-9]\+ regole' | grep -o '[0-9]\+' | head -1)
  if [ -n "${1:-}" ] && [ "$n" != "$1" ]; then
    echo "[ERR] sul FW ci sono $n regole, attese $1 — stato PRE/POST sbagliato?"
    exit 1
  fi
}

check_std() {  # $1 = delta.txt, $2 = limite in µs
  awk -v lim="$2" '$1=="tot"{ s=$11/1000
    if (s>lim) printf "[WARN] std tot %.1f µs > criterio %s µs — tempi da scartare/ripetere\n", s, lim
    else       printf "[OK]   std tot %.1f µs (criterio %s µs)\n", s, lim }' "$1"
}

do_run() {  # $1 = pre|post, $2 = rho
  local phase=$1 rho=$2 extra="" ts dst split out sig evals
  dst="$(dir_of "$rho")/${phase}"; mkdir -p "$dst"
  split=$(split_of "$rho")
  [ "$phase" = post ] && extra="--post --rho $rho"
  echo; echo "======== ${phase^^}  rho=$rho  (split $split, ramp $RAMP) ========"
  local attempt=1 tap_n rx_n
  while :; do
    if [ "$phase" = pre ]; then check_zero "$PRE_N"; else check_zero "${POST_N:-}"; fi
    sudo ./run-redial.sh --split "$split" --cpu 2 --ramp "$RAMP" 2>&1 | tee "$dst/run.log"
    ts=$(newest_ts)
    # perdite in cattura? confronto i conteggi TAP/RX stampati da run-redial
    tap_n=$(awk '$1=="TAP:"{print $2; exit}' "$dst/run.log")
    rx_n=$(awk  '$1=="RX:"{print $2; exit}'  "$dst/run.log")
    if [ -n "$tap_n" ] && [ "$tap_n" = "$rx_n" ]; then
      echo "[OK]   cattura completa: TAP=$tap_n RX=$rx_n"
      break
    fi
    echo "[WARN] perdita in cattura (TAP=$tap_n RX=$rx_n) — cancello i file della run e ripeto (tentativo $attempt/$MAX_RETRY)"
    sudo rm -f "captures/tap_${ts}.pcap" "captures/rx_${ts}.pcap" "captures/ramp_start_${ts}.epoch" "$dst/run.log"
    attempt=$((attempt+1))
    [ "$attempt" -le "$MAX_RETRY" ] || { echo "[ERR] perdite per $MAX_RETRY run di fila — controlla banco/ring buffer, non e' sfortuna"; exit 1; }
  done
  # sudo: i pcap sono di tcpdump e le cartelle possono avere proprietari misti
  sudo mv "captures/tap_${ts}.pcap" "captures/rx_${ts}.pcap" "$dst/"
  sudo mv "captures/ramp_start_${ts}.epoch" "$dst/" 2>/dev/null || true
  sudo chown -R "$USER": "$dst"
  out=$(python3 sigma_collector_subnet.py collect -o "$dst/sigma_${phase}.json" $extra)
  echo "$out"
  # check ginocchio: rate x sigma_overall < ~130M valutazioni/s
  sig=$(echo "$out" | awk -F'= *' '/sigma_overall/{print $2; exit}')
  if [ -n "$sig" ]; then
    evals=$(awk -v s="$sig" -v r="$RATE" 'BEGIN{printf "%d", s*r/1000000}')
    if [ "$evals" -gt "$KNEE_M" ]; then
      echo "[WARN] ${evals}M valutazioni/s > ginocchio ~${KNEE_M}M — TEMPI non affidabili a questo rate (i sigma restano validi)"
    else
      echo "[OK]   carico ${evals}M valutazioni/s (ginocchio ~${KNEE_M}M)"
    fi
  fi
  ./compare-redial.py --tap "$dst/tap_${ts}.pcap" --rx "$dst/rx_${ts}.pcap" \
      --ramp "$RAMP" --rx-offset-ns "$OFFSET" --rules "$RULES" \
      --csv "$dst/delta.csv" | tee "$dst/delta.txt"
  if [ "$phase" = pre ]; then check_std "$dst/delta.txt" "$STD_PRE"; else check_std "$dst/delta.txt" "$STD_POST"; fi
  echo "[i] salvato tutto in $dst/ (pcap $ts)"
}

echo "[i] tag=$TAG  rate=$RATE  rules=$RULES  → 6 run in $BASE/ (~20 GB, ~20 min + pausa REDIAL)"
echo "[i] promemoria: timer silenziati? run solo di giorno!"

# ─── 3 run PRE ───
for RHO in $RHOS; do do_run pre "$RHO"; done

echo
echo "=================================================================="
echo " Applica REDIAL da ieiitp97:"
echo "   cd ~/redial-single-fw && unset WORKDIR && ./run-fw1-only.sh"
echo "=================================================================="
read -rp "Premi INVIO quando il FW e' in POST... "

# ─── 3 run POST ───
for RHO in $RHOS; do do_run post "$RHO"; done

# ─── confronto sigma per ogni rho ───
for RHO in $RHOS; do
  d=$(dir_of "$RHO")
  echo; echo "----------- compare sigma  rho=$RHO -----------"
  python3 sigma_collector_subnet.py compare "$d/pre/sigma_pre.json" "$d/post/sigma_post.json" \
      --rho "$RHO" | tee "$d/compare_sigma.txt"
done

# ─── riepilogo tempi ───
{
  printf '%6s %10s %10s %10s   (µs, misurati)\n' rho D_pre D_post Delta
  for RHO in $RHOS; do
    d=$(dir_of "$RHO")
    awk -v rho="$RHO" '
      FNR==NR && $1=="tot" {dp=$10/1000}
      FNR!=NR && $1=="tot" {dq=$10/1000}
      END {printf "%6s %10.2f %10.2f %10.2f\n", rho, dp, dq, dp-dq}
    ' "$d/pre/delta.txt" "$d/post/delta.txt"
  done
  echo
  echo "check incrociato — derivati dai per-net della sola run 50/50:"
  awk '
    FNR==NR && ($1=="1"||$1=="2") {pre[$1]=$10/1000}
    FNR!=NR && ($1=="1"||$1=="2") {post[$1]=$10/1000}
    END {
      n=split("0.25 0.5 0.75", r, " ")
      for (i=1;i<=n;i++) { rho=r[i]+0
        dp=(1-rho)*pre["1"]+rho*pre["2"]; dq=(1-rho)*post["1"]+rho*post["2"]
        printf "%6s %10.2f %10.2f %10.2f\n", r[i], dp, dq, dp-dq }
    }' "$(dir_of 0.5)/pre/delta.txt" "$(dir_of 0.5)/post/delta.txt"
} | tee "$BASE/summary.txt"

echo; echo "[done] campagna $TAG completata — vedi $BASE/summary.txt e riporta nel tracker."
echo "[i] rollback (ieiitp97): export WORKDIR=<dir della run> && ./start.sh pre   (o ./start.sh pre-last)"
