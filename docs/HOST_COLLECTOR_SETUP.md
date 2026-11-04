# SentinelX Host Collectors

Host collectors are customer-installed, read-only agents. They use outbound HTTPS only, are scoped to one organization, and authenticate with a one-time collector token. The token is stored in D1 as a SHA-256 hash and can be revoked from Integrations → Host Collectors.

## Enrollment

1. Sign in to SentinelX as an organization owner/admin.
2. Open **Integrations → Host Collectors → Create collector**.
3. Choose a name and platform, then create the collector.
4. Copy the one-time token immediately. SentinelX does not display it again.
5. Keep the token in an environment variable or secret manager. Never commit it to source control.

## Windows Security Event ID 4625 collector

This PowerShell collector reads Windows Security failed-logon events (Event ID 4625) and sends normalized event batches directly to the Worker.

Open PowerShell as an administrator on the Windows host, download `scripts/SentinelX_Local_Windows_Collector.ps1` from the repository, then run:

```powershell
$env:SENTINELX_COLLECTOR_API_URL = "https://sentinelx-api-gateway.aiman132046.workers.dev"
$env:SENTINELX_COLLECTOR_TOKEN = "PASTE_ONE_TIME_COLLECTOR_TOKEN"
.\SentinelX_Local_Windows_Collector.ps1
```

For continuous collection every 30 seconds:

```powershell
.\SentinelX_Local_Windows_Collector.ps1 -Continuous -IntervalSeconds 30
```

The collector keeps its checkpoint at `%LOCALAPPDATA%\SentinelX\last-security-record-id.txt`. It advances the checkpoint only after the Worker confirms that an event was accepted. Press **Ctrl+C** in that PowerShell window to stop the local process.

The Worker validates the Bearer token, derives the organization from the enrolled collector row, and stores normalized records as `telemetry_intake` / `collector_events`. Windows Event ID is stored as `4625`; the unique Windows record reference is stored separately as Source Event ID.

## Python host-health collector

The standard-library Python agent reports health checks for Sysmon, ClamAV, YARA, Suricata and Zeek. It does not collect raw Windows Security events.

Install Python 3.10+ and download `scripts/sentinelx_collector.py`. In PowerShell:

```powershell
$env:SENTINELX_URL = "https://sentinelx-api-gateway.aiman132046.workers.dev"
$env:SENTINELX_COLLECTOR_TOKEN = "PASTE_ONE_TIME_COLLECTOR_TOKEN"
python .\sentinelx_collector.py --once
```

For continuous heartbeats every five minutes:

```powershell
python .\sentinelx_collector.py --interval 300
```

The Python agent reads optional integration configuration from `GET /api/collector/config` and posts health to `POST /api/collector/heartbeat`. Press **Ctrl+C** to stop it.

## Start, stop and revoke

- **Start:** run the relevant command in a terminal on the host.
- **Stop:** press **Ctrl+C** in that terminal.
- **Revoke:** use the collector's **Revoke** action in the SentinelX GUI. This blocks future API requests from that token, but it does not remotely terminate a process already running on the host.
- **Restart:** rerun the command with a valid, non-revoked token.

The GUI displays the last heartbeat/event time and collector status. A collector with no recent heartbeat may be offline, stopped, or unable to reach the Worker.

## API contract

- Python health agent: `GET /api/collector/config`, `POST /api/collector/heartbeat`.
- Windows Security agent: `POST /api/collector/events` with `Authorization: Bearer <collector-token>`, `integrationId: windows_security`, and one or more normalized events.
- GUI reads normalized telemetry from `GET /api/telemetry` using the user's authenticated session.
- ActivePieces general data API calls require both the tenant collector token in `X-SentinelX-Org-Key` and the platform bridge key in `X-SentinelX-Bridge-Key`. The bridge key is never shared with customers.

The Worker API paths and token validation have passed production smoke tests with synthetic test events. A successful synthetic smoke test does not replace testing on the actual Windows host; verify Security log permissions, the collector's last-seen status, and the resulting telemetry row after the first real run.

## Current adapter behavior

- Sysmon: Windows service and Event Log channel readability.
- ClamAV: local executable and version check.
- YARA: local executable and version check.
- Suricata: executable/build check plus freshness of the configured/default `eve.json`.
- Zeek: executable/version check plus freshness of common `conn.log` paths.

These are host-health checks, not proof of detection efficacy. Suricata/Zeek custom log paths and full telemetry-to-investigation evaluation remain separate integration work. The collector never scans arbitrary files, quarantines files, changes firewall rules, or terminates processes.
