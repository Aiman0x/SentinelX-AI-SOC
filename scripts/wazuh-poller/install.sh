#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run with sudo: sudo bash install.sh" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required. Install python3 and retry." >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemd is required for the automatic poller service." >&2
  exit 1
fi
if ! getent group wazuh >/dev/null 2>&1; then
  echo "The Wazuh group was not found. Run this installer on the Wazuh Manager VM." >&2
  exit 1
fi
if command -v curl >/dev/null 2>&1; then
  FETCH=(curl -fsSL)
elif command -v wget >/dev/null 2>&1; then
  FETCH=(wget -qO-)
else
  echo "Install curl or wget, then retry." >&2
  exit 1
fi

BASE="https://raw.githubusercontent.com/Aiman0x/SentinelX-AI-SOC/main"
APP_DIR="/opt/sentinelx-wazuh-poller"
ENV_FILE="/etc/sentinelx-wazuh-poller.env"

echo
echo "SentinelX Wazuh Poller setup"
echo "This installs a read-only poller. Wazuh API ports remain private."
echo

read -r -p "SentinelX API URL [https://sentinelx-api-gateway.aiman132046.workers.dev]: " SX_URL
SX_URL="${SX_URL:-https://sentinelx-api-gateway.aiman132046.workers.dev}"
read -r -s -p "Paste the one-time Linux collector token from SentinelX: " SX_TOKEN
echo
read -r -p "Wazuh Manager API URL [https://127.0.0.1:55000]: " MANAGER_URL
MANAGER_URL="${MANAGER_URL:-https://127.0.0.1:55000}"
read -r -p "Wazuh Manager API read-only username: " MANAGER_USER
read -r -s -p "Wazuh Manager API password: " MANAGER_PASS
echo
read -r -p "Wazuh Indexer URL [https://127.0.0.1:9200]: " INDEXER_URL
INDEXER_URL="${INDEXER_URL:-https://127.0.0.1:9200}"
read -r -p "Wazuh Indexer read-only username: " INDEXER_USER
read -r -s -p "Wazuh Indexer password: " INDEXER_PASS
echo
read -r -p "Wazuh CA certificate path (blank if already trusted): " CA_BUNDLE
echo

for item in "$SX_TOKEN" "$MANAGER_USER" "$MANAGER_PASS" "$INDEXER_USER" "$INDEXER_PASS"; do
  if [[ -z "$item" ]]; then echo "Required value missing; no files installed." >&2; exit 1; fi
done
for url in "$SX_URL" "$MANAGER_URL" "$INDEXER_URL"; do
  if [[ "$url" != https://* ]]; then echo "All service URLs must use HTTPS." >&2; exit 1; fi
done

install -d -o root -g root -m 0755 "$APP_DIR"
"${FETCH[@]}" "$BASE/scripts/wazuh-poller/poller.py" > "$APP_DIR/poller.py"
"${FETCH[@]}" "$BASE/deploy/systemd/sentinelx-wazuh-poller.service" > /etc/systemd/system/sentinelx-wazuh-poller.service
"${FETCH[@]}" "$BASE/deploy/systemd/sentinelx-wazuh-poller.timer" > /etc/systemd/system/sentinelx-wazuh-poller.timer
chmod 0755 "$APP_DIR/poller.py"
useradd --system --no-create-home --shell /usr/sbin/nologin sentinelx-poller 2>/dev/null || true
usermod -a -G wazuh sentinelx-poller
chown root:sentinelx-poller "$APP_DIR" "$APP_DIR/poller.py"
chmod 0750 "$APP_DIR"
install -d -o sentinelx-poller -g sentinelx-poller -m 0750 /var/lib/sentinelx-wazuh-poller

export SX_URL SX_TOKEN MANAGER_URL MANAGER_USER MANAGER_PASS INDEXER_URL INDEXER_USER INDEXER_PASS CA_BUNDLE
python3 - <<'PY'
import os
from pathlib import Path
values = {
    "SENTINELX_API_URL": os.environ["SX_URL"],
    "SENTINELX_COLLECTOR_TOKEN": os.environ["SX_TOKEN"],
    "WAZUH_MANAGER_URL": os.environ["MANAGER_URL"],
    "WAZUH_API_USER": os.environ["MANAGER_USER"],
    "WAZUH_API_PASSWORD": os.environ["MANAGER_PASS"],
    "WAZUH_INDEXER_URL": os.environ["INDEXER_URL"],
    "WAZUH_INDEXER_USER": os.environ["INDEXER_USER"],
    "WAZUH_INDEXER_PASSWORD": os.environ["INDEXER_PASS"],
    "WAZUH_CA_BUNDLE": os.environ.get("CA_BUNDLE", ""),
    "WAZUH_LOOKBACK_MINUTES": "5",
    "WAZUH_BATCH_SIZE": "200",
}
def quote(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '') + '"'
path = Path("/etc/sentinelx-wazuh-poller.env")
path.write_text("".join(f"{key}={quote(value)}\n" for key, value in values.items()), encoding="utf-8")
path.chmod(0o640)
PY
chown root:sentinelx-poller "$ENV_FILE"
unset SX_TOKEN MANAGER_PASS INDEXER_PASS

systemctl daemon-reload
echo "Running a one-time connection and ingestion check..."
if ! systemctl start sentinelx-wazuh-poller.service; then
  journalctl -u sentinelx-wazuh-poller.service -n 35 --no-pager || true
  echo "Initial check failed. Timer was not enabled. Fix the reported URL, credentials or CA path, then run: sudo systemctl start sentinelx-wazuh-poller.service" >&2
  exit 1
fi
systemctl enable --now sentinelx-wazuh-poller.timer
echo
echo "Setup complete. Poller timer is enabled."
echo "Check status: sudo systemctl status sentinelx-wazuh-poller.timer"
echo "Recent logs:   sudo journalctl -u sentinelx-wazuh-poller.service -n 30 --no-pager"
echo "Stop polling:  sudo systemctl disable --now sentinelx-wazuh-poller.timer"
