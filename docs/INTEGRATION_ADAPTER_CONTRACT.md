# SentinelX Integration Adapter Contract

Status: design contract (not an installed or verified adapter)

This document defines the common contract for host-side integrations. A saved configuration is not proof that a tool is installed, running, collecting data, or healthy.

## Architecture

- Cloudflare Worker: authenticated control plane, encrypted configuration storage, health-result presentation.
- SentinelX Collector: a small host-side service/agent on the machine where a tool is installed. It performs local checks and sends signed health telemetry outbound over HTTPS.
- ActivePieces: orchestration after validated telemetry arrives; it is not a substitute for a host-side adapter.
- Wazuh: current central SIEM. The Windows Wazuh Agent is already enrolled and online; use it as the first telemetry transport where possible.

Do not expose tool control ports (Wazuh API 55000, clamd 3310, local sockets, or host admin ports) to the public internet. Prefer outbound HTTPS from the collector to the SentinelX gateway, with per-device credentials, rotation, replay protection, and least privilege.

## Common adapter result

Every adapter must return this normalized structure:

```json
{
  "schemaVersion": "1.0",
  "integrationId": "sysmon",
  "sensorId": "windows-endpoint-01",
  "observedAt": "2026-10-31T00:00:00.000Z",
  "status": "healthy",
  "checks": [
    { "name": "service", "status": "pass", "detail": "service is running" },
    { "name": "telemetry", "status": "pass", "detail": "recent events observed" }
  ],
  "metrics": { "eventsSeen": 12 },
  "version": "tool-version-if-known"
}
```

Allowed overall statuses: `healthy`, `degraded`, `unhealthy`, `not_installed`, `unknown`. Allowed check statuses: `pass`, `fail`, `warn`, `unknown`. Never return credentials, raw file contents, private keys, or sensitive event payloads in health responses.

## Adapter acceptance criteria

A tool may be marked **Verified** only when:
1. Its local executable/service is detected and its version is captured where available.
2. A real tool-specific functional check succeeds (not just a TCP port-open check).
3. Its telemetry path is tested end-to-end and a recent event/heartbeat is observed.
4. The health result is timestamped and tied to a specific sensor/host.
5. Failures and stale data downgrade the status; a saved config alone never upgrades it.

## Tool-specific checks

### Wazuh
- Control plane check: authenticate to Wazuh API over trusted HTTPS and query agent inventory.
- Telemetry check: confirm the expected agent is Active and recent agent events are indexed.
- Current deployment: Wazuh Manager/Indexer/Dashboard on the Azure VM; Windows endpoint agent `SentinelX-Windows-01` is enrolled and has been observed Active.
- Security: API must remain private. Use a Cloudflare Tunnel with Access service credentials or a private collector bridge; do not open TCP/55000 publicly. The current Worker-side API test requires a trusted HTTPS route before it can pass.

### Windows Sysmon
- Local check: detect Sysmon service and driver; query `Microsoft-Windows-Sysmon/Operational`.
- Telemetry check: verify Wazuh Agent collects that channel and that recent Sysmon event IDs are searchable centrally.
- Do not claim verified based only on a config version string.

### ClamAV
- Local check: detect `clamd` and `clamscan`; run a harmless version/status command.
- Functional check: use a harmless test file in a controlled test directory; do not quarantine or delete user files during health checks.
- Keep clamd bound to loopback/private network. Never expose TCP/3310 publicly.

### YARA
- Local check: detect YARA executable and readable rules directory; compile/load rules.
- Functional check: run a known benign test fixture and assert expected rule behavior.
- Do not scan arbitrary user directories as part of a connection test.

### Suricata
- Local check: detect service and configuration validity.
- Telemetry check: parse the latest valid record from `eve.json` and confirm timestamps are fresh.
- A running service without fresh EVE records is degraded, not verified.

### Zeek
- Local check: detect service and log directory.
- Telemetry check: parse recent `conn.log`/JSON records and verify fresh timestamps.
- A configured path without fresh logs is not verified.

## Implementation order

1. Keep current Wazuh agent enrollment as the first working telemetry source.
2. Secure Wazuh API reachability with Tunnel/Access or a private bridge.
3. Add Sysmon channel collection and prove events appear in Wazuh.
4. Build the Windows Collector service with read-only checks and outbound HTTPS.
5. Add ClamAV and YARA host adapters.
6. Add Suricata and Zeek sensor adapters on a separate network sensor host.
7. Connect validated adapter events to ActivePieces workflows.

## Operational safety

- All health checks are read-only except explicitly approved test fixtures.
- No automatic containment, deletion, quarantine, firewall edits, or process termination from a health check.
- Use per-sensor identity, short-lived or rotatable credentials, request timestamps/nonces, and rate limits.
- Treat tool output and logs as untrusted input.
- Keep secrets in encrypted backend storage; never mirror secret values into browser local storage or logs.
- Display **Saved**, **Reachable**, **Telemetry observed**, and **Verified** as distinct states.
