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


## Live event ingestion pipeline

Security telemetry enters one tenant-scoped pipeline:
- **Host collectors:** `POST /api/collector/events` with `Authorization: Bearer <collector-token>` and JSON `{ "integrationId": "sysmon|suricata|zeek|...", "events": [...] }`.
- **Webhook/Activepieces:** `POST /api/events/ingest` with `X-SentinelX-Bridge-Key`, `X-SentinelX-Org-Key: <collector-token>`, and JSON `{ "source": "activepieces|wazuh|...", "events": [...] }`. Tenant identity is resolved from the enrolled collector token, never from payload fields.
- Both paths validate and normalize events, then publish to Cloudflare Queue `sentinelx-events`. A successful HTTP `202` means queued for processing, not yet persisted.
- The queue consumer writes the normalized event and sanitized raw event to D1 `security_events`. Unique `(org_id,dedup_key)` prevents duplicate delivery from creating duplicate rows.
- The common schema includes schema version, source, event ID/type, severity, observed/received timestamps, host, source/destination IP, username and message. Raw source data is retained after secret-field scrubbing.
- Queue delivery retries failures up to five times with delay; exhausted messages are routed to `sentinelx-events-dlq` for inspection/replay. Queue retention is configured by Cloudflare Queue settings.
- `GET /api/events?limit=100` returns only the authenticated user's organization events.

The Worker owns the queue consumer. The D1 table is created by migration `0004_security_events.sql`; on the currently connected production database this schema was applied and verified. Do not send a tenant/org ID in event payloads to select a tenant.

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


## Universal BYOT connector framework

The production Worker exposes a versioned connector registry at `GET /api/integrations` and a capability catalog at `GET /api/integrations/capabilities`. Each adapter follows the same lifecycle: schema discovery, connect/update, live test, read-only query when supported, and disconnect. The UI reads the server registry and renders each adapter's fields and capabilities rather than storing provider credentials in browser storage.

Initial connector coverage:
- **Wazuh:** Manager API authentication, agent inventory and Indexer alert search. Use a trusted HTTPS route (for example Cloudflare Tunnel + Access); do not expose Manager/Indexer ports directly.
- **VirusTotal / AbuseIPDB:** tenant-user-owned API keys and read-only indicator lookups. VirusTotal queries may contribute indicators to its shared dataset; avoid confidential or personal indicators.
- **Sysmon / Suricata / Zeek:** collector-reported sensor health and tenant-scoped telemetry queries.
- **ClamAV / YARA:** collector-reported scanner/rule-engine health and tenant-scoped scan-result queries. These require the relevant tool to be installed on a customer-owned host and an enrolled collector to report its health; SentinelX does not install or execute scanners remotely.
- **ActivePieces:** gateway-managed workflow bridge; no customer API key is entered in the connector form.
- **Cloudflare Response:** separately approval-gated action connector; excluded from the read-only AI query catalog.

Connector credentials are encrypted at rest in tenant- and user-scoped KV entries. The browser receives configured field names and health metadata only, never secret values. Reconnect updates the saved configuration; disconnect removes the current user's connector configuration and health state. Organization-shared, non-secret host settings are retained while another organization member still has that connector configured. Viewer users cannot change connector configuration. A saved configuration is not considered connected until its live test passes.

## Fixed platform LLM and SOC agent

SentinelX uses one centrally managed agent identity and one fixed model for every customer workspace:
- **Agent:** SentinelX SOC Investigator v1
- **Provider:** OpenRouter
- **Model:** `nvidia/nemotron-3-ultra:free`
- **Model selection:** fixed server-side; customers cannot select an agent, provider, model, or fallback.
- **API key:** entered only by an explicitly registered SentinelX platform administrator in Settings → Integration settings. It is encrypted at rest in KV with AES-GCM and a platform-wide associated-data key. The browser receives only configured status, never the key.
- **Platform admin authorization:** D1 `platform_admins` allowlist. Migration `0007_platform_admins.sql` bootstraps the existing workspace owner(s) once; future tenant owners are not automatically promoted.
- **Privacy:** common secrets and direct identifiers are masked before model requests. Masking is always enabled for the agent.
- **Budget:** model input is bounded (1,000–12,000 estimated tokens; default 6,000). The model adapter uses OpenRouter's OpenAI-compatible chat completions API.

The selected NVIDIA Nemotron 3 Ultra `:free` variant is listed at $0 input/output token pricing on OpenRouter. Free-tier capacity and rate limits apply, and availability can change. API usage uses the shared SentinelX platform OpenRouter key.

## Read-only autonomous agent loop

The investigation workspace exposes the fixed SentinelX SOC Investigator v1 at `POST /api/ai/agent`.

1. The model creates a short investigation plan.
2. The gateway supplies only query-capable connectors configured for the authenticated user.
3. The fixed model selects one connector from the tools connected to the authenticated user and one schema-valid query at a time; the gateway validates the tool ID and every input field before execution.
4. Tool results are treated as untrusted evidence, masked when masking is enabled, bounded before being sent back to the model, and used to re-plan until the model finishes or the hard limit is reached.
5. The model returns a conclusion with evidence and uncertainty.

Safety controls: maximum five tool calls (server-enforced; client cannot change the limit), read-only connector query allowlist, no shell/response/remediation tools, strict audit start and completion/failure records for every connector call, and a system-level prompt-injection guard that treats logs and tool results as untrusted data. Audit creation fails closed: a connector query is not run if its audit start record cannot be written. Agent output remains advisory and requires analyst review.


## Blue-team reporting and analyst workflows

- The investigation workspace includes **Threat hunt** and **Phishing triage** prompt presets for the bounded read-only agent. The analyst supplies the hypothesis, alert, email or indicators; the agent may query only connectors configured for that signed-in user.
- `POST /api/ai/report` generates tenant-scoped daily, weekly or case-specific incident reports. Reports include evidence-backed candidate MITRE ATT&CK mappings, uncertainty and defensive recommendations; they are stored as `soc_report` records and audit logged.
- Cloudflare Worker Cron is configured for daily (02:00 UTC) and weekly (Monday 03:00 UTC) report generation. Scheduled reports run only for active organizations with an AI provider configured and are stored in D1. Provider billing is charged to the configured provider account.
- Cron/report generation does not perform containment or remediation. MITRE mappings are candidate mappings requiring analyst validation.
- **Monitoring limitation:** collectors currently push normalized Sysmon/Suricata/Zeek events into tenant-scoped D1. Fully autonomous alert-to-agent investigation/queue processing and host-side Sysmon/Suricata/Zeek deployment scripts remain separate implementation work; do not interpret scheduled reports as continuous autonomous response.


## Detection, correlation and evidence engine

New tenant-scoped Worker APIs:
- `GET /api/detections/rules` — built-in and tenant-defined detection rules.
- `POST /api/detections/rules` — Owner/Admin creates or updates a rule. JSON fields: `ruleKey`, `title`, optional `description`, `ruleType` (`sigma` or `builtin`), `sigmaYaml`, `definition`, `severity`, `confidence`, and optional `mitre`.
- `DELETE /api/detections/rules?ruleKey=...` — Owner/Admin disables a tenant rule.
- `GET /api/detections/findings` or `GET /api/incidents` — tenant-scoped incidents and severity/confidence.
- `GET /api/incidents/{id}` — incident, correlated events and supporting evidence.
- `GET /api/evidence?incidentId=...` — preserved evidence snapshots.
- `GET /api/evidence/verify?id=...` — recomputes SHA-256 and checks evidence integrity.

Newly persisted queue events are evaluated before queue acknowledgement. A per-event processing marker allows retries to resume detection if a failure occurs after event persistence. Incident/event/evidence writes are idempotent. Evidence stores the normalized event plus scrubbed raw event, detection rule, MITRE mapping, capture time and SHA-256 digest.

Built-in detections cover repeated authentication failures, failed-logon-then-success sequences, suspicious script interpreters, persistence-related activity, remote service activity and periodic outbound patterns. Sigma support intentionally implements a safe, documented subset: field equality, lists, `|contains`, `|startswith`, `|endswith`, and common `and`/`or`/ `1 of`/`all of` selection conditions. It is not a complete SigmaHQ backend pipeline; unsupported modifiers and correlation rules must not be treated as supported.

Severity is rule-driven and escalates when a stronger matching rule is observed. Confidence is an explainable rule score (1–100), not a probability that compromise is confirmed. Findings remain analyst-review candidates.
