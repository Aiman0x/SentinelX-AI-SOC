# SentinelX Wazuh Linux Poller

A small, read-only Python 3 poller that runs beside Wazuh on the Linux VM. It queries the Wazuh Manager API for agent inventory count and the Wazuh Indexer for recent `wazuh-alerts-*` documents, then forwards normalized alerts to SentinelX through the existing tenant-scoped Linux host-collector endpoint.

## Security model

- All Wazuh credentials stay in a root-owned environment file on the Wazuh VM.
- The poller makes outbound HTTPS requests only; it does not expose Manager or Indexer ports.
- The SentinelX collector token is stored locally and can be revoked from Host Collectors.
- TLS certificate verification is enabled. Configure `WAZUH_CA_BUNDLE` for a private/self-signed Wazuh CA; do not set an insecure TLS mode.
- The Wazuh account should be read-only and limited to agent read and alert-index read permissions.
- Recent alerts are re-read with a configurable lookback window. SentinelX deduplicates using the stable Wazuh index/document identifier.

## Install on the Wazuh Linux VM

1. Create a Linux host collector in SentinelX **Host Collectors** and copy its token once. Do not paste the token into chat or commit it.
2. Copy `scripts/wazuh-poller/poller.py` to `/opt/sentinelx-wazuh-poller/poller.py`.
3. Create a restricted service account and install the service files:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin sentinelx-poller 2>/dev/null || true
sudo install -d -o root -g sentinelx-poller -m 0750 /opt/sentinelx-wazuh-poller
sudo install -o root -g sentinelx-poller -m 0750 scripts/wazuh-poller/poller.py /opt/sentinelx-wazuh-poller/poller.py
sudo install -o root -g root -m 0644 deploy/systemd/sentinelx-wazuh-poller.service /etc/systemd/system/
sudo install -o root -g root -m 0644 deploy/systemd/sentinelx-wazuh-poller.timer /etc/systemd/system/
sudo install -o root -g root -m 0600 scripts/wazuh-poller/sentinelx-wazuh-poller.env.example /etc/sentinelx-wazuh-poller.env
sudo chown root:sentinelx-poller /etc/sentinelx-wazuh-poller.env
sudo chmod 0640 /etc/sentinelx-wazuh-poller.env
sudoedit /etc/sentinelx-wazuh-poller.env
```

Fill the environment file locally with the collector token and dedicated read-only Wazuh Manager/Indexer credentials. Keep the URLs loopback/internal when the poller runs on the same VM. If the Wazuh services use a private CA, set `WAZUH_CA_BUNDLE` to its certificate path.

4. Test once, then enable the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl start sentinelx-wazuh-poller.service
sudo journalctl -u sentinelx-wazuh-poller.service -n 30 --no-pager
sudo systemctl enable --now sentinelx-wazuh-poller.timer
systemctl list-timers sentinelx-wazuh-poller.timer
```

To stop polling: `sudo systemctl disable --now sentinelx-wazuh-poller.timer`. Revoke the Linux collector in SentinelX if the VM is decommissioned.

## Current limits

- Each run reads at most `WAZUH_BATCH_SIZE` alerts (maximum 500) from the last `WAZUH_LOOKBACK_MINUTES` (maximum 60). Increase polling frequency or tune the window/batch size if alert volume exceeds this bound.
- Agent inventory is checked for connectivity and reported in the service log; alert documents are ingested into the SentinelX event pipeline.
- This integration is read-only: it does not acknowledge alerts, modify agents, or run response actions.
