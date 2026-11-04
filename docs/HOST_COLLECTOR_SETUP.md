# SentinelX Host Collector

The host collector is a customer-installed, read-only agent. It performs local health checks and reports normalized adapter health to the SentinelX Worker over outbound HTTPS. It does not expose local service ports or send raw log contents.

## Enrollment
1. Sign in to SentinelX as organization owner/admin.
2. Open Integrations → Host Collectors → Create collector.
3. Copy the one-time token and keep it secret.
4. Install Python 3.10+ on the host and download `scripts/sentinelx_collector.py`.
5. Run with the deployed Worker URL and token:
   ```powershell
   $env:SENTINELX_URL="https://YOUR-SENTINELX-WORKER"
   $env:SENTINELX_COLLECTOR_TOKEN="ONE_TIME_TOKEN"
   python .\sentinelx_collector.py --once
   ```
   For continuous monitoring omit `--once`. On Linux/macOS use the same environment variables and Python command.
6. Confirm last-seen time and adapter status in the GUI. Revoke the collector from the GUI if the token is compromised.

## Windows Security Event ID 4625 intake

The separate read-only PowerShell prototype sends failed-logon telemetry directly to the Worker; it does not use the legacy ActivePieces webhook header pair.

1. Enroll a Windows collector in Integrations → Host Collectors and copy its one-time token.
2. Configure `SENTINELX_COLLECTOR_API_URL` as the deployed Worker base URL (for example, `https://your-worker.example.workers.dev`) and `SENTINELX_COLLECTOR_TOKEN` as the issued collector token.
3. The PowerShell collector sends batches to `POST /api/collector/events` with `Authorization: Bearer <collector-token>` and `integrationId: windows_security`.
4. The Worker validates the token hash, derives the organization from the enrolled collector row, and stores normalized records as `telemetry_intake` / `collector_events`. The GUI reads these through `GET /api/telemetry`.
5. Verify the event in Windows Telemetry and verify collector last-seen status. Do not treat a successful response as a full end-to-end pass until both are checked.

The Windows Security path is implemented in the Worker source but is not yet runtime-tested or deployed. Do not run a collector against production until the Worker deployment is confirmed and an organization admin has intentionally enrolled the collector.

## Current adapter behavior
- Sysmon: Windows service and Event Log channel readability.
- ClamAV: local executable and version check.
- YARA: local executable and version check.
- Suricata: executable/build check plus freshness of default `/var/log/suricata/eve.json`.
- Zeek: executable/version check plus freshness of common `conn.log` paths.

These are host-health checks, not proof of detection efficacy or end-to-end alert ingestion. Suricata/Zeek custom log paths and actual telemetry-to-ActivePieces forwarding are subsequent adapter work. The collector never scans arbitrary files, quarantines files, changes firewall rules, or terminates processes.

## Security
Tokens are shown once, hashed in D1, scoped to one organization and collector, and can be revoked. Keep tokens in environment variables or a secret manager, not in source control. Use HTTPS only. Heartbeat payloads contain tool status/check metadata, not raw security events.
