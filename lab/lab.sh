#!/usr/bin/env bash
# Local VPSPilot lab: Linux VMs (via Lima) that behave like real VPSes, with
# systemd and their own network stack. The agent in each VM reaches the API
# on your Mac at http://host.lima.internal:<port>.
#
#   ./lab/lab.sh up                 create the lab VMs
#   ./lab/lab.sh status             list VMs and whether the API is reachable
#   ./lab/lab.sh enroll web-1 ept_...            enroll with a token (no quoting needed)
#   ./lab/lab.sh enroll web-1 ept_... https://x.ngrok-free.app   ...via another API URL
#   ./lab/lab.sh enroll web-1 '<install command from the dashboard>'
#   ./lab/lab.sh shell web-1        open a shell in a VM
#   ./lab/lab.sh stop web-2         stop a VM (watch it go offline)
#   ./lab/lab.sh start web-2
#   ./lab/lab.sh down               delete all lab VMs
set -euo pipefail

# name  template           cpus  memory(GiB)  disk(GiB)
VMS=(
  "web-1 ubuntu-24.04 2 1.5 12"
  "web-2 debian-12    1 1   8"
)
API_PORT="${API_PORT:-8000}"

need_lima() {
  command -v limactl >/dev/null || { echo "Install Lima first: brew install lima" >&2; exit 1; }
}

exists() { limactl list --format '{{.Name}}' 2>/dev/null | grep -qx "$1"; }

cmd_up() {
  need_lima
  for spec in "${VMS[@]}"; do
    read -r name template cpus memory disk <<<"$spec"
    if exists "$name"; then
      echo "==> $name exists; starting"
      limactl start "$name" --tty=false >/dev/null 2>&1 || true
    else
      echo "==> creating $name ($template, ${cpus} CPU, ${memory} GiB RAM)"
      limactl start --name "$name" --cpus "$cpus" --memory "$memory" --disk "$disk" \
        --tty=false "template:$template" >/dev/null
    fi
  done
  cmd_status
}

cmd_status() {
  need_lima
  limactl list
  echo
  for spec in "${VMS[@]}"; do
    read -r name _ <<<"$spec"
    exists "$name" || continue
    if limactl shell "$name" -- curl -fsS -m 3 "http://host.lima.internal:${API_PORT}/health" >/dev/null 2>&1; then
      echo "$name → API on :${API_PORT} reachable"
    else
      echo "$name → API on :${API_PORT} NOT reachable (is it running?)"
    fi
  done
}

cmd_enroll() {
  local name="${1:?vm name}" arg="${2:?enrollment token (ept_...) or quoted install command}"
  if [[ "$arg" == ept_* ]]; then
    # Just the token: build the install command against the API on this Mac
    # (or the URL given, e.g. an ngrok tunnel).
    local url="${3:-http://host.lima.internal:${API_PORT}}"
    url="${url%/}"
    echo "==> Enrolling $name via $url"
    limactl shell "$name" -- bash -c "curl -fsSL '$url/agent/install.sh' | sudo bash -s -- --token '$arg' --url '$url'"
  elif [[ "$arg" == *"|"* ]]; then
    limactl shell "$name" -- bash -c "$arg"
  else
    echo "Pass the token (ept_...) or the whole install command in single quotes." >&2
    echo "Without quotes your shell runs the part after '|' on this Mac instead of the VM." >&2
    exit 2
  fi
}

case "${1:-}" in
  up) cmd_up ;;
  status) cmd_status ;;
  enroll) shift; cmd_enroll "$@" ;;
  shell) limactl shell "${2:?vm name}" ;;
  stop) limactl stop "${2:?vm name}" ;;
  start) limactl start "${2:?vm name}" --tty=false ;;
  down)
    need_lima
    for spec in "${VMS[@]}"; do
      read -r name _ <<<"$spec"
      exists "$name" && limactl delete --force "$name"
    done
    ;;
  *) sed -n '2,13p' "$0"; exit 2 ;;
esac
