# ActivePieces tenant-scoped service authentication

## Purpose

ActivePieces is a trusted platform automation service. A host collector credential must never authenticate general case, note, approval, or SOC-record APIs. Collector credentials are accepted only by dedicated `/api/collector/*` endpoints.

## Request sequence

1. ActivePieces receives an event that carries the collector token in `X-SentinelX-Org-Key` (or the normalized `org_token` field).
2. Before making any general data API request, ActivePieces calls:
   - `GET /api/collector/context`
   - `Authorization: Bearer <collector-token>`
3. The Worker validates the token hash against `host_collectors`, checks `revoked_at IS NULL`, and returns the collector's `organizationId` and `collectorId`. This endpoint does not return case data or grant data API access.
4. ActivePieces makes tenant-scoped data requests with both:
   - `X-SentinelX-Bridge-Key: <AP_BRIDGE_KEY>`
   - `X-SentinelX-Org-ID: <organizationId-from-context>`

The Worker verifies the bridge secret, verifies that the organization is active, and constructs a service actor bound to that organization. Every D1 query continues to use the actor's organization ID.

**Trust boundary:** `AP_BRIDGE_KEY` is a platform-wide credential, not a tenant credential. The central ActivePieces project is trusted to act for any active organization when it supplies that organization's ID after collector-context resolution. A tenant must never receive this bridge key. If the deployment later gives each customer a separate ActivePieces project, replace this central credential with independently issued, organization-scoped service credentials before enabling customer-controlled workflows.

## Service allowlist

The service actor may:
- Read tenant cases and SOC records.
- Read the existing read-only findings, investigations, evidence, audit, assets, rules, and telemetry routes.
- Create only the approved `sx_cases_v1` and `sentinelx_cases` case schemas.
- Update an existing case in its own organization.
- Upsert SOC records in its own organization.

The service actor may not:
- Create notes or approvals.
- Decide or execute approvals.
- Enroll, list, configure, or revoke collectors.
- Access another organization without a separate trusted request carrying that organization's verified ID.

Normal analyst sessions continue to use the session cookie. Collector tokens continue to use Bearer authentication only on collector routes.

## Required ActivePieces follow-up

The Worker code change is not sufficient by itself. Before deploying it, update the relevant ActivePieces flows to add the context lookup and replace `X-SentinelX-Org-Key` on D1 API calls with the bridge key plus the resolved organization ID. Do not send a collector token to `/api/cases` or `/api/records`.

The currently published flows still contain the old header contract and `failureMode: continue_none`; leave them unchanged until the Worker and flow changes can be deployed together. Change HTTP failure handling to stop on non-2xx responses and add explicit retries only to idempotent requests.

## Secret handling

`AP_BRIDGE_KEY` remains a Cloudflare Worker secret. The existing ActivePieces flow definitions contain a literal bridge credential in their HTTP step settings; do not copy it into source code, logs, issue comments, or documentation. Plan a coordinated credential rotation after the new contract is deployed and verified. This change does not rotate or revoke any credential.
