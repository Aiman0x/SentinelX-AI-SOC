# SentinelX — AI-Assisted Security Operations Center

SentinelX is a multi-tenant, BYO-integrations AI SOC platform focused on authorized telemetry ingestion, detection, investigation, evidence handling, and analyst-guided response. Each workspace can connect its own supported security tools and configure its own LLM provider; no single Wazuh server or model provider is mandatory.

The intended design uses a **Cloudflare Worker** as the authenticated control plane and a **React GUI** for workspace management. **ActivePieces** remains an optional/reusable workflow orchestration layer. Tool and model credentials are workspace-scoped and stored server-side.

## Architecture

```text
Authorized security telemetry
        |
        v
ActivePieces intake, validation and detection workflows
        |
        v
SentinelX tables: findings, cases, investigations, evidence, assets, rules, audit
        ^
        |
Cloudflare Worker (single public origin)
  - serves React GUI static assets
  - analyst password login and signed session
  - authenticated read routes to ActivePieces
  - encrypted integration configuration storage
        ^
        |
Browser — SentinelX SOC GUI
```

The intended public origin is `https://sentinelx-api-gateway.aiman132046.workers.dev`. GitHub remains the source repository; GitHub Actions builds the frontend and deploys the GUI assets and API gateway together.

## Implemented

- Dark black/red/gold SOC GUI with alerts, cases, investigations, assets, integrations, detection rules, playbooks, audit logs, and settings.
- Backend-aware GUI data loaders and mappers for alerts, cases, investigations, evidence references, assets, rules, audit logs, and integrations.
- Cloudflare Worker source with PBKDF2 analyst-password verification, signed HttpOnly session cookies, login rate limiting, and origin restriction.
- Cloudflare D1 SOC data plane with tenant-scoped `org_id` on every workspace-owned data table; tenant scope is taken from the authenticated session, never trusted from browser input.
- D1-backed case, finding, investigation, evidence, audit, asset, rule, and telemetry read routes; case, note, and approval write routes with tenant checks and audit events.
- Authenticated read routes from the GUI through D1; ActivePieces remains the workflow/orchestration layer while legacy table writers are being retired.
- Encrypted workspace-scoped integration configuration using AES-256-GCM and Workers KV.\n- BYO-LLM settings and encrypted per-workspace provider credentials for OpenAI, Anthropic, Gemini, and OpenAI-compatible HTTPS endpoints.\n- Server-side provider connection tests and an authenticated AI investigation endpoint; analyst role can run investigations while workspace admins manage provider credentials.
- Workers Static Assets configuration to serve the GUI and route `/api/*` requests through the same Worker origin.

## Data migration and ActivePieces status

- Existing Activepieces table data was imported into D1: 69 case records from both legacy case schemas, 167 other SOC records, and 1 approval record (237 total). Legacy organization labels, including `ORG-DEFAULT`, were normalized to the owning D1 organization ID during import.
- The two legacy case schemas are now represented in one D1 `cases` table with `source_schema` retained for traceability.
- Eight obsolete `ARCHIVE v0` flows were deleted from the ActivePieces project. Current enabled flows were preserved.
- The old ActivePieces case tables and active flows are retained temporarily because enabled workflows still reference them. They must not be deleted until those writers/readers are migrated to the D1 gateway and validated.
- One enabled callable flow (`SentinelX - SOC Alert Triage`) still contains the legacy `ORG-DEFAULT` value. It must be changed to accept only a trusted, authenticated `org_id` from its upstream caller before that flow can safely write tenant data; simply replacing the literal with caller-controlled JSON would not provide tenant isolation.
- A D1 migration file is stored at `cloudflare-worker/migrations/0002_soc_data.sql`.

## Deployment prerequisites

- Add `CLOUDFLARE_API_TOKEN` as a GitHub Actions secret with permission to deploy Workers Scripts.
- Generate the analyst password hash, session HMAC secret, and AES encryption key locally.
- Rotate the shared GUI bridge credential on all eight ActivePieces read workflows.
- Configure the eight published ActivePieces webhook URLs as Worker Secrets.

See `cloudflare-worker/README.md` for the exact runtime secret names and setup instructions. See `docs/BYO_LLM_AND_MULTI_TENANT_ARCHITECTURE.md` for the target BYO-LLM and multi-tenant connector design.

## Still pending

- Deploy and verify the combined Cloudflare Worker.
- Configure Worker secrets and ActivePieces webhook URLs.
- Migrate enabled ActivePieces ingestion/detection workflows from legacy Tables writes to tenant-bound D1 gateway writes; remove the remaining `ORG-DEFAULT` flow dependency; then remove the two legacy ActivePieces case tables.
- Wire GUI case creation/status changes and analyst notes to the new gateway write routes.
- Add asset and detection-rule write APIs.
- Build tool-specific adapters and health checks for Wazuh, Sysmon, Suricata, Zeek, ClamAV, and YARA.
- Add a workspace provider API key in Settings and run a live connection test (requires a customer-owned provider key).
- Validate real Windows and authorized remote telemetry.
- Add audited, human-approved defensive response workflows.

## Run locally

Requirements: Node.js 18+ and npm.

```bash
npm install
npm run dev
npm run build
npm run preview
```

Without `VITE_API_BASE_URL`, the GUI uses demo data. Never put secrets in `VITE_*` variables or frontend source.

## D1 gateway routes

- `GET /api/cases`, `POST /api/cases`, and `POST /api/cases/{caseId}`
- `POST /api/notes` and `GET /api/notes?caseId=...`
- `GET /api/approvals`, `POST /api/approvals`, and `POST /api/approvals/{approvalId}/decision`
- Read routes for alerts, investigations, evidence, audit logs, assets, rules, and telemetry now query D1 by the authenticated `org_id`.
- Viewer accounts are read-only. Approval decisions require owner/admin role. Approval decisions never execute the requested response action; execution remains `Not Executed`.

## Security principles

- Use SentinelX only with systems and data you are authorized to monitor.
- Never commit API keys, webhook URLs, bridge keys, passwords, or encryption keys.
- Keep credentials in server-side secret storage and encrypt integration secrets before persistence.
- Do not describe demo data, saved configurations, or structurally valid workflows as verified telemetry or connected tools.
- Keep disruptive response actions disabled until authentication, approval, and audit controls are implemented.

**Status: In Development — D1 schema and tenant-scoped gateway routes are implemented on the feature branch; existing ActivePieces workflows still require migration, and deployment/live verification remain pending.**
