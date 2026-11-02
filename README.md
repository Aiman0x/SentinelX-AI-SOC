# SentinelX — Activepieces-first AI SOC

SentinelX is a defensive SOC investigation platform. Activepieces orchestrates ingestion, detection, investigation and response workflows; Cloudflare Worker + D1 provide the authenticated multi-tenant API and durable data plane.

## Current architecture

- **Frontend:** React/Vite SOC console.
- **Gateway:** Cloudflare Worker with session authentication, role checks, CORS, collector enrollment and tenant-scoped data routes.
- **Database:** Cloudflare D1. Tenant-owned records are scoped by `org_id`; the organization ID is derived from the authenticated analyst session or an organization-specific collector token.
- **Automation:** Activepieces workflows for telemetry intake, Windows security events, detections, correlation, and verification.
- **Collector enrollment:** Integrations → Host Collectors. Each collector receives a unique token shown once.

## Multi-tenant data model

The D1 migration `cloudflare-worker/migrations/0002_soc_data.sql` creates the SOC data plane. The connected D1 database has these tenant-scoped tables:

- `cases`
- `notes`
- `approvals`
- `soc_records` (findings, telemetry, incoming events, evidence, integrations, assets, rules, investigations, timeline and other extensible records)
- `audit_logs`
- `host_collectors`
- `organization_memberships`
- `auth_sessions`
- `auth_audit_log` (nullable `org_id` only for pre-authentication events)

`users` remains a global identity table because one person may belong to multiple organizations. `organizations.id` is the organization identifier. Memberships and sessions bind a user to one active organization; new sessions require `org_id`.

The auth-scope SQL already applied to the connected D1 database is documented in `cloudflare-worker/manual-migrations/0003_auth_org_scope.sql`. It is outside Wrangler's automatic migrations directory because it has already been applied manually to the existing database.

## D1 gateway routes

- `GET /api/cases`, `GET /api/cases/:caseId`, `POST /api/cases`, `POST /api/cases/:caseId`
- `GET /api/notes?caseId=...`, `POST /api/notes`
- `GET /api/approvals`, `POST /api/approvals`, `POST /api/approvals/:approvalId/decision`
- `GET /api/records?entity_type=...`, `POST /api/records` for tenant-scoped SOC record types
- `GET /api/collectors`, `POST /api/collectors`, `DELETE /api/collectors/:id`

The browser cannot choose its tenant by sending `org_id`. Analyst requests use the organization bound to the signed session. Activepieces-to-D1 requests use `X-SentinelX-Org-Key`; the Worker hashes the token and resolves its organization through `host_collectors`. The token is never accepted from a record's JSON payload.

## Activepieces migration

The following workflows now use D1 for their primary SOC data writes/reads:

- Phase 3 telemetry intake
- Windows failed-login case intake
- SOC alert triage (cases, incoming events, audit records, tool registry and telemetry context)
- Repeated-authentication, failed-then-success, endpoint-security and network/posture findings
- Correlation investigations and timeline entries
- Post-action verification audit
- Asset coverage audit

The legacy case records were copied to D1 before cleanup: **69 cases** from the populated legacy case table (the second duplicate contained 0 rows), plus **167 other SOC records** and **1 approval** (237 migrated records total). Both legacy Activepieces case tables were then deleted. Their `source_schema` values remain in D1 for traceability.

The two obsolete Activepieces approval intake/decision flows and the obsolete incident-record read proxy were removed because the Worker now owns those gateway routes. The eight `ARCHIVE` flows were already absent from the Activepieces project when checked; no active flow was deleted under that label.

Other Activepieces tables remain as legacy/reference data during the wider transition. The 19 legacy audit rows and 19 incoming-event rows that still carried `ORG-DEFAULT` were normalized to the real organization UUID; a project-wide scan found no remaining `ORG-DEFAULT` values in table records or active flow definitions. D1 is the source of truth for the migrated case, telemetry, event, finding, investigation, timeline, asset, audit and approval paths.

## Collector setup

1. In the SentinelX console, open **Integrations → Host Collectors**.
2. Create a collector for the target Windows/Linux/macOS host and copy its token. It is shown only once.
3. Configure the collector with `SENTINELX_ORG_TOKEN`.
4. In addition to the existing Activepieces webhook header `X-SentinelX-Key`, send `X-SentinelX-Org-Key: <collector-token>`.
5. Do not put an organization ID or `ORG-DEFAULT` into the event payload to select a tenant. The Worker resolves the tenant from the token.

For the existing Windows PowerShell collector, add the organization token to the request headers alongside the current webhook key. The collector's local script is not changed by this repository update.

## Security notes

- Read-only viewer accounts cannot write.
- Case, note and approval writes are tenant-scoped.
- Approval decisions require an owner/admin session.
- Approval decisions do not execute containment actions; response execution remains separately gated.
- Collector tokens are hashed in D1 and can be revoked from Host Collectors.
- D1 queries always bind `org_id` from the authenticated context.

## Deployment and validation

- The implementation is on `feat/byo-llm-multi-tenant-integrations`.
- `validate-multitenant.yml` builds the frontend and bundles the Worker without deploying.
- `deploy-worker.yml` applies the automatic D1 migration and deploys the Worker on updates to `main`.
- The connected D1 schema/data changes have been applied. The updated Worker code is committed on the feature branch and the critical Activepieces flows validate successfully (zero invalid steps). The Worker code has not yet been deployed from this branch; merge/deploy is a separate release step.


## Connect your tools — connector framework

The feature branch includes a dynamic Connect your tools page backed by the Worker connector registry. Each adapter exposes connect(), test(), query() and a versioned schema. The UI renders the registry schema dynamically.

- Per-user credentials are encrypted at rest with AES-GCM and scoped to the signed-in user + organization + connector. Secrets are never returned to the browser.
- Wazuh adapter connects both Manager API and Indexer: agent inventory, agent lookup, manager info and recent alert search. Use a private/trusted HTTPS route such as Cloudflare Tunnel + Access; never expose port 55000 publicly.
- Sysmon, Suricata and Zeek adapters use host-collector health, authenticated event ingestion at /api/collector/events, and tenant-scoped D1 telemetry queries.
- VirusTotal, AbuseIPDB and URLScan use each user's own API key and read-only reputation/search lookups.
- ActivePieces remains gateway-managed and appears in the same registry.
- Connector connect/test/query operations are audit logged without credentials or IOC values.

Provider live status requires the user to add their own credentials and pass the real test. Sysmon/Suricata/Zeek require an enrolled collector on the endpoint or network sensor. VirusTotal lookups can contribute queried indicators to its shared dataset; do not submit sensitive or personal indicators, and review its API terms before product use.
