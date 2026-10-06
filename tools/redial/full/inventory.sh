export D0_CIDR="10.0.0.0/24"
export D1_CIDR="10.0.3.0/24"
export D2_LIST_CIDR="10.0.2.0/24"
export DN_LIST_CIDR="10.0.1.0/24"

export SSH_USER="drago"
export GEN_IP="192.168.100.101"
export FW1_IP="192.168.100.103"
export FW2_IP="192.168.100.104"
export FW1_INNER_IP="10.0.3.1"
export FW2_INNER_IP="10.0.3.2"
export FW2_UPSTREAM_IFACES="eth0"

export PASS_FILE="$HOME/redial/.fwpass"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o LogLevel=ERROR)

# WORKDIR sticky: si crea solo se non già esportato (es. da una shell padre)
if [[ -z "${WORKDIR:-}" ]]; then
    export WORKDIR="$HOME/redial/runs/$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$WORKDIR"

fw_run() {
    local host="$1"; shift
    local cmd="$*"
    sshpass -f "$PASS_FILE" ssh "${SSH_OPTS[@]}" "$SSH_USER@$host" \
        "sudo -S -p '' bash -c \"$cmd\"" < "$PASS_FILE"
}

fw_pipe() {
    local host="$1"; shift
    local cmd="$*"
    { cat "$PASS_FILE"; cat; } | sshpass -f "$PASS_FILE" ssh "${SSH_OPTS[@]}" \
        "$SSH_USER@$host" "sudo -S -p '' bash -c \"$cmd\""
}

fw_scp_to() {
    local local_file="$1" host="$2" remote_path="$3"
    sshpass -f "$PASS_FILE" scp "${SSH_OPTS[@]}" "$local_file" \
        "$SSH_USER@$host:$remote_path"
}

export -f fw_run fw_pipe fw_scp_to
echo "[inventory] WORKDIR=$WORKDIR"

# Network namespace in cui gira il firewall vero su ciascun host
export FW1_NETNS="FW"
export FW2_NETNS="FW2"
