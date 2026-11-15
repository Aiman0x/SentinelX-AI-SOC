# Connect Wazuh to SentinelX (Linux)

## Customer setup

Wazuh uses the existing SentinelX Cloudflare Worker gateway. No separate Wazuh gateway, Cloudflare Tunnel, public Manager API port, or public Indexer port is required.

1. In SentinelX, open **Tools → Host collectors**.
2. Select **Linux · Wazuh server**, enter a friendly name, and choose **Enroll host**.
3. Copy the one-time command.
4. Open a terminal on the Linux VM that runs Wazuh and run the command with sudo.
5. The installer prompts locally for the one-time collector token and the Wazuh Manager API / Indexer read-only credentials. Passwords are hidden while typing and saved only in a root-owned environment file on that VM.
6. The installer performs a live connection/ingestion check. It enables the one-minute systemd timer only after that check succeeds.
7. Return to **Tools** and press **Test** on Wazuh. The status becomes verified after the VM reports a fresh healthy heartbeat.

The default Manager and Indexer URLs are loopback (https://127.0.0.1:55000 and https://127.0.0.1:9200) because the poller runs beside Wazuh. If services use another private address or port, enter that internal HTTPS URL during installation.

## Security

- Manager and Indexer credentials never enter the SentinelX browser or Cloudflare Worker.
- The poller uses read-only Manager API and Indexer search operations.
- TLS verification is enabled. If Wazuh uses a private CA, provide the CA certificate path during setup; never disable certificate verification.
- The Linux collector token is stored in /etc/sentinelx-wazuh-poller.env, owned by root and readable only by the poller service group.
- The VM initiates outbound HTTPS requests to SentinelX. No inbound firewall/NSG rules are required for Manager API or Indexer.
- Alerts enter the existing tenant-scoped event queue and D1 security-event pipeline. Wazuh events are deduplicated by their stable Indexer document identity.

## Operations

~~~bash
# Check timer
sudo systemctl status sentinelx-wazuh-poller.timer

# Check last poll
sudo journalctl -u sentinelx-wazuh-poller.service -n 30 --no-pager

# Run a one-off poll
sudo systemctl start sentinelx-wazuh-poller.service

# Pause automatic polling
sudo systemctl disable --now sentinelx-wazuh-poller.timer

# Resume automatic polling
sudo systemctl enable --now sentinelx-wazuh-poller.timer
~~~

Use **Pause** in SentinelX to reject incoming telemetry without deleting enrollment. Use **Remove** to revoke the collector token; then stop the VM timer and remove the local service if decommissioning.

## Implementation details

- Poller: scripts/wazuh-poller/poller.py
- Installer: scripts/wazuh-poller/install.sh
- systemd unit/timer: deploy/systemd/
- Worker ingestion: POST /api/collector/events
- Health: POST /api/collector/heartbeat
- Read-only investigation queries run against tenant-scoped normalized Wazuh events in SentinelX, not directly against a customer-exposed Indexer endpoint.

## Current limits

The poller checks a rolling lookback window (default five minutes) and sends up to 500 alerts per run. Stable document IDs prevent duplicate rows when windows overlap. If sustained alert volume exceeds the configured batch size, tune the polling window/batch size and validate queue throughput before production use.
