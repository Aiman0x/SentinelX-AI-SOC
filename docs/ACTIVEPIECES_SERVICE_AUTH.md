# ActivePieces tenant-scoped service authentication

## Purpose

ActivePieces is a trusted platform automation service. A tenant collector token identifies the organization, while the platform bridge key proves that the request came from the trusted ActivePieces project. Neither credential is sufficient by itself.

## Request contract

For every ActivePieces request to the Worker data APIs, send both:

- `X-SentinelX-Org-Key: <tenant collector token>`
- `X-SentinelX-Bridge-Key: <AP_BRIDGE_KEY>`

The Worker hashes the collector token using the same SHA-256/base64url scheme used by collector enrollment, resolves its active `host_collectors` row, checks that it is not revoked, verifies the platform bridge secret, and binds the service actor to that collector's active organization.

The old `X-SentinelX-Org-ID` contract remains supported for trusted internal service calls that already have a verified organization ID. It is not a substitute for the tenant token on externally triggered tenant workflows.

**Important:** `X-SentinelX-Org-Key` must contain a real, non-revoked collector token created for that tenant. An arbitrary string or the old webhook secret is not accepted. The collector token alone cannot access general data APIs.

## Trust boundary

`AP_BRIDGE_KEY` is a platform-wide credential, not a tenant credential. The central ActivePieces project is trusted to act for a tenant only when it also presents that tenant's valid collector token. Never expose the bridge key in the GUI, to customers, or in collector scripts. If each customer later receives a separate ActivePieces project, replace this central credential with independently issued organization-scoped service credentials before enabling customer-controlled workflows.

## Service allowlist

The service actor may:
- Read tenant cases and SOC records.
- Read findings, investigations, evidence, audit, assets, rules, telemetry, and approval status.
- Create only the approved `sx_cases_v1` and `sentinelx_cases` case schemas.
- Update an existing case in its own organization.
- Upsert SOC records in its own organization.

The service actor may not:
- Create notes or approvals.
- Decide or execute approvals.
- Enroll, list, configure, or revoke collectors.
- Access another organization without that organization's valid collector token.

Normal analyst sessions continue to use the session cookie. Collector tokens continue to use Bearer authentication on dedicated `/api/collector/*` routes; on ActivePieces data requests they are paired with the bridge key and used only to resolve the tenant.

## ActivePieces flow contract

- Webhook/callable flow payloads must carry the tenant's collector token as `X-SentinelX-Org-Key` (or the normalized `org_token` value that downstream steps forward).
- Every Worker `/api/cases`, `/api/records`, and read-only `/api/approvals` HTTP action must send both headers above.
- The Worker must never accept a collector token without the bridge key.
- HTTP action `failureMode: continue_none` means **do not continue; stop the flow on failure**. Do not change this to a continue mode. Retry is disabled for non-idempotent POST operations; use retries only for safe, idempotent reads.

The relevant active flows have been updated in the current ActivePieces draft. Validate them and publish them together with the Worker change. Do not publish an untested draft.

## Secret handling

`AP_BRIDGE_KEY` remains a Cloudflare Worker secret. The ActivePieces flow definitions contain the matching credential in their HTTP step settings; do not copy it into source code, logs, issue comments, or customer-facing documentation. Rotate it only as a coordinated Worker + ActivePieces change.

## Pre-deployment security test matrix

Run these against a disposable test database or isolated staging environment; do not use production records for destructive tests.

| Test | Expected result |
|---|---|
| Valid collector token + correct bridge key | Service actor bound to that collector's organization |
| Valid collector token without bridge key | 401 |
| Incorrect bridge key, even with a valid collector token | 401 |
| Revoked or unknown collector token | 401 |
| Collector token used alone on a general data API | 401 |
| Valid token + bridge key reads cases/records | Only that organization’s rows |
| Tenant A token requests a case belonging to B | 404 |
| Service actor reads approval status | 200, organization-scoped |
| Service actor creates notes or approvals/decision | 403 |
| Service actor creates a case with an unapproved schema | 403 |
| Service actor creates an approved case schema | 201 and an Automation audit row |
| Normal analyst session reads and writes within its own organization | Existing role rules remain unchanged |

The platform-wide bridge credential is a trusted-service boundary, not a customer-facing credential.
