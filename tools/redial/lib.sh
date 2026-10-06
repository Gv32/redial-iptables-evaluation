#!/usr/bin/env bash

source ./inventory.sh

die() {
  echo "[ERR] $*" >&2
  exit 1
}

fw1() {
  sshpass -f "$PASS_FILE" ssh \
    -o StrictHostKeyChecking=accept-new \
    -o ConnectTimeout=10 \
    "$SSH_USER@$FW1_MGMT" "$@"
}

fw1_sudo() {
  sshpass -f "$PASS_FILE" ssh \
    -o StrictHostKeyChecking=accept-new \
    -o ConnectTimeout=10 \
    "$SSH_USER@$FW1_MGMT" \
    "sudo -S -p '' $*" < "$PASS_FILE"
}

fw1_put() {
  local src="$1"
  local dst="$2"

  sshpass -f "$PASS_FILE" scp \
    -o StrictHostKeyChecking=accept-new \
    -o ConnectTimeout=10 \
    "$src" "$SSH_USER@$FW1_MGMT:$dst"
}
