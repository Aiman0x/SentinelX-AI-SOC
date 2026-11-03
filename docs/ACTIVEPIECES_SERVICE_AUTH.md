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

## Pre-deployment security test matrix

Run these against a disposable test database or isolated staging environment; do not use production records for destructive tests.

| Test | Expected result |
|---|---|
| Valid collector token calls `GET /api/collector/context` | 200 with only its organization and collector IDs |
| Revoked or unknown collector token calls context | 401 |
| Collector token calls `GET /api/cases` or `/api/records` | 401 |
| Bridge key missing or incorrect | 401 |
| Valid bridge key with missing/malformed/inactive organization ID | 401 |
| Valid bridge key + organization A reads cases/records | Only organization A rows |
| Valid bridge key + organization A requests a case belonging to B | 404 |
| Service actor posts to notes or approvals/decision | 403 |
| Service actor creates a case with an unapproved schema | 403 |
| Service actor creates a case using `sx_cases_v1` or `sentinelx_cases` | 201 and an Automation audit row |
| Normal analyst session reads and writes within its own organization | Existing role rules remain unchanged |

Also verify two organizations can both use the central automation service while every query remains bound to the organization ID returned by the authenticated collector-context call. The platform-wide bridge credential is a trusted-service boundary, not a customer-facing credential.
