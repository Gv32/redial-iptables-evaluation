###############################################################################
# REDIAL — workflow completo (apply-only, NO persistenza)
# Eseguire sul bastion, già loggato come 'drago'.
# Le regole nuove vengono applicate SOLO in RAM (non sopravvivono al reboot).
# Il rollback ai backup è MANUALE (sezione finale, commentata).
#
# NB1: 'sshpass' fornisce la password solo a SSH. 'sudo' sui FW ha la sua
# autenticazione: la passiamo via stdin con 'sudo -S' (l'helper fw_sudo qui
# sotto fa esattamente questo). Assumiamo che la password sudo di drago sia
# la STESSA della password SSH (file $PASS_FILE).
#
# NB2: il firewall vero gira DENTRO una network namespace su ciascun host
# (FW1_NETNS=FW, FW2_NETNS=FW2). Tutti i comandi iptables/iptables-restore
# DEVONO essere wrappati con 'ip netns exec $NETNS …', altrimenti agiscono
# sul namespace di default dell'host e NON sul firewall reale.
# Per evitare di dimenticarsene, qui sotto c'è l'helper dedicato fw_ns.
###############################################################################

cd ~/redial

# ─── 0. Helpers ──────────────────────────────────────────────────────────────
# fw_put  HOST SRC DST          → scp di un file dal bastion al FW
# fw_sudo HOST CMD...           → sudo CMD sul FW (namespace di default)
# fw_ns   HOST NETNS CMD...     → sudo ip netns exec NETNS CMD sul FW
fw_put() {
  local host="$1" src="$2" dst="$3"
  sshpass -f "$PASS_FILE" scp -o StrictHostKeyChecking=accept-new \
    "$src" "$SSH_USER@$host:$dst"
}
fw_sudo() {
  local host="$1"; shift
  cat "$PASS_FILE" | sshpass -f "$PASS_FILE" ssh -o StrictHostKeyChecking=accept-new \
    "$SSH_USER@$host" "sudo -S -p '' $*"
}
fw_ns() {
  local host="$1" netns="$2"; shift 2
  cat "$PASS_FILE" | sshpass -f "$PASS_FILE" ssh -o StrictHostKeyChecking=accept-new \
    "$SSH_USER@$host" "sudo -S -p '' ip netns exec $netns $*"
}

# ─── 1. Setup ambiente ───────────────────────────────────────────────────────
# Esporta variabili (D0_CIDR, D2_LIST_CIDR, DN_LIST_CIDR, FW1_IP, FW2_IP,
# FW1_NETNS, FW2_NETNS, SSH_USER, PASS_FILE) e crea $WORKDIR = ~/redial/runs/<timestamp>
source ./inventory.sh
echo "WORKDIR = $WORKDIR"

# Sanity check: senza i nomi delle netns lo script applicherebbe nel posto
# sbagliato (è il bug che avevamo). Fermati subito se mancano.
[ -n "$FW1_NETNS" ] && [ -n "$FW2_NETNS" ] \
  || { echo "[FATAL] FW1_NETNS / FW2_NETNS non settate in inventory.sh"; return 1 2>/dev/null || exit 1; }

# ─── 2. Scarica le regole correnti da FW1 e FW2 ──────────────────────────────
# Produce nel WORKDIR:
#   fw1.backup.rules   ← iptables-save di FW1 (snapshot per rollback)
#   fw1.xml            ← stesse regole in formato iptables-xml
#   fw2.backup.rules   ← iptables-save di FW2
#   fw2.xml
# NB: collect.sh DEVE wrappare i comandi con 'sudo ip netns exec $FWx_NETNS …'
# (NON 'iptables-save' diretto), perché il firewall vero gira nella netns.
./collect.sh
ls -la "$WORKDIR"

# ─── 3. Applica REDIAL → genera le nuove regole ──────────────────────────────
# Produce:
#   fw1.new.rules  ← FW1 alleggerito (con shortcut verso D^K_1)
#   fw2.new.rules  ← FW2 con catena custom REDIAL_A_0 + regole originali
./run_redial.py \
  --fw1-xml "$WORKDIR/fw1.xml" \
  --fw2-xml "$WORKDIR/fw2.xml" \
  --d0  "$D0_CIDR" \
  --d2  "$D2_LIST_CIDR" \
  --dn  "$DN_LIST_CIDR" \
  --fw2-iface "$FW2_UPSTREAM_IFACES" \
  --out-fw1 "$WORKDIR/fw1.new.rules" \
  --out-fw2 "$WORKDIR/fw2.new.rules"

# ─── 4. Carica le nuove regole sui FW (in /tmp) e validale (dry-run) ─────────
# Copiamo i file sui FW perché 'sudo -S' usa già stdin per la password,
# quindi non possiamo passare le regole anche via stdin di ssh.
fw_put "$FW1_IP" "$WORKDIR/fw1.new.rules" /tmp/redial_fw1.rules
fw_put "$FW2_IP" "$WORKDIR/fw2.new.rules" /tmp/redial_fw2.rules

# NB: niente 'exit 1' qui: se la validazione fallisce non vogliamo
# uccidere la shell del bastion (chiuderebbe la sessione SSH dal laptop).
# Se vedi [ABORT], NON proseguire alla sezione 5 per quel FW.
fw_ns "$FW1_IP" "$FW1_NETNS" "iptables-restore --test /tmp/redial_fw1.rules" \
  && echo "[OK] fw1.new.rules sintassi valida" \
  || echo "[ABORT] fw1.new.rules NON valido — NON eseguire la sezione 5 per FW1"

fw_ns "$FW2_IP" "$FW2_NETNS" "iptables-restore --test /tmp/redial_fw2.rules" \
  && echo "[OK] fw2.new.rules sintassi valida" \
  || echo "[ABORT] fw2.new.rules NON valido — NON eseguire la sezione 5 per FW2"

# ─── 5. Applica le nuove regole (in RAM) ─────────────────────────────────────
# ⚠️ Da qui in poi le regole sono attive sui FW. Se qualcosa va storto,
#    vai direttamente alla sezione "ROLLBACK MANUALE" in fondo.
fw_ns "$FW1_IP" "$FW1_NETNS" "iptables-restore /tmp/redial_fw1.rules" && echo "[OK] FW1 applicato"
fw_ns "$FW2_IP" "$FW2_NETNS" "iptables-restore /tmp/redial_fw2.rules" && echo "[OK] FW2 applicato"

# ─── 6. (Persistenza SALTATA volutamente) ─────────────────────────────────────
# Le regole restano in RAM. Al primo reboot dei FW spariranno.
# Per riapplicarle, rilancia le sezioni 4 e 5 dal bastion: il WORKDIR è sticky
# e i file fw{1,2}.new.rules sono ancora nel run-dir.

# ─── 7. Verifica post-apply ──────────────────────────────────────────────────
echo "=== FW1 FORWARD (prime 20 regole) ==="
fw_ns "$FW1_IP" "$FW1_NETNS" "iptables -L FORWARD -n --line-numbers" | head -20
echo "=== FW2 FORWARD (prime 20 regole) ==="
fw_ns "$FW2_IP" "$FW2_NETNS" "iptables -L FORWARD -n --line-numbers" | head -20
echo "=== FW2 catena custom REDIAL_A_0 (se presente) ==="
fw_ns "$FW2_IP" "$FW2_NETNS" "iptables -L REDIAL_A_0 -n --line-numbers 2>/dev/null" \
  || echo "(catena REDIAL_A_0 non presente)"

echo "[DONE] REDIAL applicato (solo RAM, non persistente). Backup pre-REDIAL in: $WORKDIR"
