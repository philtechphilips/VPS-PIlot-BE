#!/usr/bin/env bash
# VPSPilot agent installer.
#   curl -fsSL __API_URL__/agent/install.sh | sudo bash -s -- --token ept_...
set -euo pipefail

API_URL="__API_URL__"
TOKEN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --token) TOKEN="$2"; shift 2 ;;
    --url) API_URL="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

[ -n "$TOKEN" ] || { echo "Missing --token (create one in the dashboard)" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "Run as root: ... | sudo bash -s -- --token ..." >&2; exit 1; }

. /etc/os-release
case "$ID" in
  ubuntu|debian) ;;
  *) echo "Unsupported OS: $PRETTY_NAME. VPSPilot supports Ubuntu and Debian." >&2; exit 1 ;;
esac

echo "==> VPSPilot agent installer"
echo "    $PRETTY_NAME · $(uname -m) · control plane $API_URL"

export DEBIAN_FRONTEND=noninteractive
# Keep apt quiet: no needrestart prompts or reports during install.
export NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1
echo "==> Installing dependencies (python3, python3-psutil)"
apt-get update -qq
apt-get install -y -qq python3 python3-psutil curl ca-certificates >/dev/null

echo "==> Creating unprivileged user 'vpspilot'"
id vpspilot >/dev/null 2>&1 || useradd --system --home /var/lib/vpspilot --shell /usr/sbin/nologin vpspilot
install -d -m 0755 /opt/vpspilot-agent
install -d -m 0750 -o vpspilot -g vpspilot /etc/vpspilot /var/lib/vpspilot

echo "==> Downloading agent"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$API_URL/agent/package.tar.gz" -o "$tmp/agent.tar.gz"
rm -rf /opt/vpspilot-agent/vpspilot_agent
tar -xzf "$tmp/agent.tar.gz" -C /opt/vpspilot-agent

echo "==> Enrolling with the control plane"
runuser -u vpspilot -- env PYTHONPATH=/opt/vpspilot-agent \
  python3 -m vpspilot_agent enroll --url "$API_URL" --token "$TOKEN" --config /etc/vpspilot/agent.json

echo "==> Installing systemd service"
cat > /etc/systemd/system/vpspilot-agent.service <<'UNIT'
[Unit]
Description=VPSPilot agent
After=network-online.target
Wants=network-online.target

[Service]
User=vpspilot
Group=vpspilot
Environment=PYTHONPATH=/opt/vpspilot-agent
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 -m vpspilot_agent run --config /etc/vpspilot/agent.json
Restart=always
RestartSec=5
# 78 = revoked/not enrolled: restarting would not help.
RestartPreventExitStatus=78
# Hardening: the agent only reads system state and talks to the API.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ReadWritePaths=/var/lib/vpspilot /etc/vpspilot
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now vpspilot-agent >/dev/null 2>&1
systemctl restart vpspilot-agent

echo "==> Done. The agent is running; this server will appear online in the dashboard."
echo "    Logs: journalctl -u vpspilot-agent -f"
