# SentinelX Defensive Integrations

## Implemented connector registry

The Cloudflare Worker hosts a dynamic connector registry. Each adapter exposes the standard methods `connect()`, `test()`, `query()` and a versioned `schema`. The Connect your tools page renders fields and query controls from that registry.

| Connector | Status in code | Capabilities |
|---|---|---|
| Wazuh | Implemented | Manager API auth, agent inventory, agent details, Manager info, Indexer alert search |
| Windows Sysmon | Implemented | Collector health, event ingestion, tenant-scoped event query |
| Suricata | Implemented | Collector health, eve.json event ingestion, tenant-scoped event query |
| Zeek | Implemented | Collector health, Zeek event ingestion, tenant-scoped event query |
| VirusTotal | Implemented | User-owned API key, read-only IP/domain/URL/hash lookups |
| AbuseIPDB | Implemented | User-owned API key, read-only IP reputation checks |
| URLScan | Implemented | User-owned API key, quotas test, historical scan search |
| ActivePieces | Implemented | Gateway-managed bridge health check |

## Credentials and security

- Credentials are encrypted using AES-256-GCM in Worker KV and scoped by organization + authenticated user + connector.
- Secrets are never returned to the browser and are not written to audit logs.
- Viewer accounts cannot save connector credentials.
- Use dedicated read-only Wazuh Manager and Indexer accounts.
- Wazuh API and Indexer endpoints must use trusted HTTPS. Keep ports 55000 and 9200 private behind Cloudflare Tunnel + Access or a private bridge; do not expose them publicly.
- VirusTotal lookups may add queried indicators to its shared dataset. Never submit sensitive, confidential or personal indicators. Review VirusTotal API terms before product use.
- Threat-intel connectors perform lookups only; URLScan adapter does not submit new scans.

## Host telemetry

Create a SentinelX Host Collector and use its one-time token:
- POST /api/collector/heartbeat for tool health reports.
- POST /api/collector/events for normalized Sysmon, Suricata or Zeek event batches.
- The Worker resolves org_id from the collector token; clients cannot select another tenant.
- Event ingestion strips common credential fields and stores records in tenant-scoped D1 soc_records.

## Verification boundary

Implementation is committed on `feat/byo-llm-multi-tenant-integrations`. A connector is not live-connected just because credentials were saved. Wazuh requires the user's own reachable Manager + Indexer endpoints and read-only credentials, followed by a successful test. Sysmon/Suricata/Zeek require an enrolled collector and recent health/events. Provider API keys must be supplied by each user; no shared SentinelX keys are bundled.

The Worker and frontend changes are not yet deployed from this feature branch.
