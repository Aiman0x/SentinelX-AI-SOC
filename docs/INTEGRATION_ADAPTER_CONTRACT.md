# SentinelX Integration Adapter Contract

Status: implemented connector registry and adapters on feat/byo-llm-multi-tenant-integrations. A provider is only shown as Verified after its live test or collector telemetry succeeds.

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


## Implemented connector API (registry v1.0)

The Cloudflare Worker exposes a registry-driven API. The frontend renders the returned schema.fields and schema.query.fields; it does not maintain a second hard-coded catalog.

- GET /api/integrations — current user's registry entries, schema, configured field names and health state (never secret values).
- GET /api/integrations/:id/schema — versioned adapter schema.
- POST /api/integrations/:id/connect — validate and save that user's credentials/configuration.
- POST /api/integrations/:id/test — real provider or host-collector health check.
- POST /api/integrations/:id/query — provider-specific, read-only query.

Every adapter implements connect(), test(), query() and exposes schema. Credentials are encrypted with AES-256-GCM in Worker KV and keyed by organization + authenticated user + connector ID. The browser receives configured field names only, never secret values. Connector actions are audit logged without storing credentials or IOC values.

### Implemented adapters

| Adapter | Connect | Test | Query |
|---|---|---|---|
| Wazuh | User-owned Manager API + Indexer read-only usernames/passwords and optional Cloudflare Access service token | Authenticate to Manager, retrieve agent inventory, and search the Wazuh alert index | List agents, get one agent, manager info, recent alerts |
| Windows Sysmon | Sensor/channel metadata | Fresh collector health report | Tenant-scoped Sysmon records from D1 |
| Suricata | Sensor / eve.json source metadata | Fresh collector health report | Tenant-scoped Suricata records from D1 |
| Zeek | Sensor / log source metadata | Fresh collector health report | Tenant-scoped Zeek records from D1 |
| VirusTotal | User-owned API key | Read-only IP report check | IP, domain, URL and file-hash reports |
| AbuseIPDB | User-owned API key | Read-only IP check | IP reputation / abuse-confidence lookup |
| URLScan | User-owned API key | Read-only quota check | Search historic scans by IP, domain, URL or hash |
| ActivePieces | Gateway-managed bridge | Verify configured bridge webhook | Uses SentinelX SOC/workflow routes |

Wazuh API access is restricted to a public HTTPS hostname; private/local IPs, embedded credentials, and non-HTTPS URLs are rejected. Use Cloudflare Tunnel + Access service credentials or a private outbound bridge. Never expose Wazuh TCP/55000 to the public internet.

### Threat-intelligence privacy

All three threat-intel adapters use the current user's own API key and read-only lookups. AbuseIPDB supports IP addresses only. VirusTotal documentation warns that queried indicators may be added to its shared dataset; do not query confidential, personal, or sensitive indicators. Check VirusTotal's API terms and licensing before using a Community API key in a product. URLScan searches historical scan data; this adapter does not submit new URLs for scanning.

### Verification boundary

The connector code and API contract are implemented. Wazuh cannot be marked live-connected until an administrator supplies a reachable trusted HTTPS API endpoint and that user's own read-only Wazuh credentials. Sysmon, Suricata and Zeek need a collector installed on the respective endpoint/sensor and fresh health/telemetry reports. Provider API keys are never bundled with SentinelX; each user supplies their own.


### Host collector event ingestion

Sysmon, Suricata and Zeek adapters use the authenticated collector pipeline. After creating a host collector, send health reports to POST /api/collector/heartbeat and normalized event batches to POST /api/collector/events with Authorization: Bearer <collector-token>. The event body is { integrationId: 'sysmon' | 'suricata' | 'zeek', events: [{ eventId, observedAt, payload }] }. Batches accept 1–100 events and are stored in D1 soc_records using the organization resolved from the collector token, never from caller-supplied org_id. The ingestion layer strips common credential fields before storage and deduplicates per collector + event ID. The connector query adapters then read only that organization's matching records.

## LLM gateway contract

The Worker LLM gateway supports a primary provider plus up to three fallback provider configurations. Every provider entry has a provider ID, model, BYO API key and optional HTTPS base URL for OpenAI-compatible endpoints. Keys are encrypted in KV with AES-GCM and are never returned to the browser.

Before analysis, the gateway optionally masks common secret-value pairs, bearer tokens, email addresses and phone numbers. It then applies a configurable approximate input budget (500–12,000 tokens; default 6,000; ~4 characters/token) and truncates excess evidence. Responses include the selected provider/model, fallback count, estimated input tokens, configured budget, masking status and truncation status.

Masking is best-effort and not a guarantee of anonymization. Provider requests can still disclose submitted evidence to the selected third-party provider. Do not send credentials, regulated personal data or confidential telemetry unless the organization has approved that provider and its data terms.
