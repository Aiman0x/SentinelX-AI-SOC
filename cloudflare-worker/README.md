# SentinelX Cloudflare Worker

The Worker serves the SentinelX GUI and authenticated multi-tenant API. Cloudflare D1 is the SOC data plane; Activepieces is the workflow/orchestration layer.

## Required bindings

- `DB`: D1 database binding.
- `ALLOWED_ORIGIN`: allowed SentinelX frontend origin.
- `SESSION_SECRET`: secret used to sign analyst sessions.
- `AP_BRIDGE_KEY`: retained for the Worker-to-Activepieces health/read integrations that still use the legacy webhook bridge.
- `AP_WEBHOOK_KEY` and the configured Activepieces webhook URLs: used by the remaining Activepieces health and orchestration integrations.

The D1 data routes do **not** accept a shared bridge key or an organization ID supplied in a JSON body. Activepieces uses an organization-specific collector token in `X-SentinelX-Org-Key`.

## D1 schema

- `migrations/0002_soc_data.sql`: creates `cases`, `notes`, `approvals`, `soc_records`, `audit_logs`, and `host_collectors`, all with `org_id`.
- `manual-migrations/0003_auth_org_scope.sql`: records the auth-scope migration already applied to the connected D1 database. It renames membership `organization_id` to `org_id`, adds `org_id` to sessions and auth audit rows, backfills existing rows, and rejects new sessions without an organization.

`users` is a global identity table; `organizations.id` is the organization identifier. A membership binds a user to an organization, and every new session stores that `org_id`. The `currentUser` lookup joins the session and membership on the same `org_id`.

## API routes

### Analyst-session routes

- `GET /api/cases` and `GET /api/cases/:caseId`
- `POST /api/cases` and `POST /api/cases/:caseId`
- `GET /api/notes?caseId=...` and `POST /api/notes`
- `GET /api/approvals` and `POST /api/approvals`
- `POST /api/approvals/:approvalId/decision`
- `GET /api/records?entity_type=...`

The organization is taken from the signed session. A browser-supplied `org_id` is ignored. Viewer-role users are read-only; approval decisions require owner/admin.

### Activepieces service routes

- `GET /api/cases` and `GET /api/cases/:caseId`
- `POST /api/cases` and `POST /api/cases/:caseId`
- `GET /api/records?entity_type=...` and `POST /api/records`
- `GET /api/approvals?approval_id=...`
- `POST /api/approvals`
- `POST /api/notes`

For these routes, Activepieces sends `X-SentinelX-Org-Key`. The Worker SHA-256 hashes the token, looks up the hash in `host_collectors`, checks that the organization is active, and derives `org_id` from that row. No `org_id` in the event body is trusted.

`POST /api/records` supports one record or a batch of up to 200 records. The D1 uniqueness key is `(org_id, entity_type, source_table, source_record_id)`, so retries upsert within the same tenant and cannot overwrite another tenant's record.

### Collector enrollment

- `GET /api/collectors`
- `POST /api/collectors`
- `DELETE /api/collectors/:id`

Only an owner/admin analyst session can enroll or revoke a collector. The raw token is returned once; only its hash is stored in D1.

## Activepieces webhook headers

The existing webhook authentication header `X-SentinelX-Key` remains for the Activepieces webhook trigger. A host collector must also send its own tenant token:

```powershell
$headers = @{
  "X-SentinelX-Key" = $env:SENTINELX_WEBHOOK_KEY
  "X-SentinelX-Org-Key" = $env:SENTINELX_ORG_TOKEN
}
```

Do not send `ORG-DEFAULT` or an untrusted `organization_id` field to select the tenant.

## Local development and deployment

From the repository root:

```bash
npm ci
npm run build
npx wrangler@4 deploy --dry-run --config cloudflare-worker/wrangler.toml
```

The GitHub Actions deploy workflow applies the automatic D1 migration before deploying the Worker to Cloudflare. The manual auth-scope migration is already applied to the existing D1 database and is deliberately outside Wrangler's automatic migration directory to avoid replaying its non-idempotent `ALTER TABLE` statements.
