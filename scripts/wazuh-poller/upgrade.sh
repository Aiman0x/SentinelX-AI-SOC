#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo: sudo bash /tmp/sentinelx-wazuh-upgrade.sh" >&2
  exit 1
fi

APP_DIR="/opt/sentinelx-wazuh-poller"
ENV_FILE="/etc/sentinelx-wazuh-poller.env"
SERVICE_FILE="/etc/systemd/system/sentinelx-wazuh-poller.service"
BASE="https://raw.githubusercontent.com/Aiman0x/SentinelX-AI-SOC/main"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

if [[ ! -f "$ENV_FILE" || ! -x "$APP_DIR/poller.py" ]]; then
  echo "Existing SentinelX Wazuh poller installation was not found. Use the Host Collectors enrollment setup first." >&2
  exit 1
fi
if ! id sentinelx-poller >/dev/null 2>&1; then
  echo "sentinelx-poller service account is missing; refusing to change the existing setup." >&2
  exit 1
fi
if ! getent group wazuh >/dev/null 2>&1; then
  echo "Wazuh group was not found; run this on the Wazuh Manager VM." >&2
  exit 1
fi
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO- "$1"; }
else
  echo "Install curl or wget, then retry." >&2
  exit 1
fi

echo "Updating SentinelX Wazuh poller without changing its saved credentials..."
fetch "$BASE/scripts/wazuh-poller/poller.py" > "$TMP_DIR/poller.py"
fetch "$BASE/deploy/systemd/sentinelx-wazuh-poller.service" > "$TMP_DIR/sentinelx-wazuh-poller.service"
python3 -m py_compile "$TMP_DIR/poller.py"
usermod -a -G wazuh sentinelx-poller
install -o root -g sentinelx-poller -m 0750 "$TMP_DIR/poller.py" "$APP_DIR/poller.py"
install -o root -g root -m 0644 "$TMP_DIR/sentinelx-wazuh-poller.service" "$SERVICE_FILE"

systemctl daemon-reload
systemctl enable --now sentinelx-wazuh-poller.timer
if ! systemctl start sentinelx-wazuh-poller.service; then
  journalctl -u sentinelx-wazuh-poller.service -n 35 --no-pager || true
  echo "Poller update installed, but the immediate check failed. The timer remains enabled; inspect the service logs." >&2
  exit 1
fi

echo
echo "SentinelX Wazuh poller update completed."
echo "The existing collector token and Wazuh credentials were preserved."
echo "Timer status:"
systemctl status sentinelx-wazuh-poller.timer --no-pager
echo
echo "Latest poller result:"
journalctl -u sentinelx-wazuh-poller.service -n 12 --no-pager
