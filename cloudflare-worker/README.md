# SentinelX Cloudflare API Gateway

Read-only gateway between the GitHub Pages frontend and the existing Activepieces GUI read workflows.

## Security requirements

- Protect the Worker hostname with a Cloudflare Access application and an allow policy for the intended analyst.
- Configure the Access team domain and application AUD tag. The Worker independently verifies the Access JWT.
- Store the Activepieces bridge key as a Worker secret. Never put it in GitHub source, Vite variables, or browser code.
- Restrict CORS to https://aiman0x.github.io.
- Only GET routes are implemented. No case updates, notes, playbook execution, or defensive actions are exposed in this phase.
- Origin/CORS checks are not authentication. Cloudflare Access is required.

## Deploy

From this directory, use Wrangler:

    npx wrangler deploy

## Worker variables

Set these non-secret variables:

- ALLOWED_ORIGIN = https://aiman0x.github.io
- CF_ACCESS_TEAM_DOMAIN = your-team.cloudflareaccess.com
- CF_ACCESS_AUD = the Access application's AUD tag
- AP_READ_DETECTION_FINDINGS_URL
- AP_READ_INCIDENT_RECORDS_URL
- AP_READ_INVESTIGATIONS_URL
- AP_READ_EVIDENCE_REFERENCES_URL
- AP_READ_AUDIT_LOGS_URL
- AP_READ_ASSETS_URL
- AP_READ_DETECTION_RULES_URL
- AP_READ_SECURITY_INTEGRATIONS_URL

Set AP_BRIDGE_KEY as a Worker secret. It must match the rotated X-SentinelX-Bridge-Key credential configured on the eight Activepieces read workflows. Do not reuse the telemetry ingestion key.

Copy each webhook URL from its corresponding published Activepieces workflow trigger. Do not commit webhook URLs or credentials to Git.

## Read-only route mapping

| Frontend route | Activepieces workflow |
|---|---|
| GET /api/alerts | Read Detection Findings |
| GET /api/cases | Read Incident Records |
| GET /api/investigations | Read Investigations |
| GET /api/evidence | Read Evidence References |
| GET /api/audit | Read Audit Logs |
| GET /api/assets | Read Assets |
| GET /api/rules | Read Detection Rules |
| GET /api/integrations | Read Security Integrations |
| GET /health | Worker process health only |

The Worker unwraps a top-level data property from the Activepieces response when present. Mapping table records to the frontend TypeScript interfaces must be verified against real records before enabling live dashboard data.

## Known frontend integration work

The current frontend API client uses credentialed fetch requests. The frontend must be updated to the Cloudflare Access authentication flow before enabling live API mode. The gateway intentionally fails closed when Access is not configured or a valid Access JWT is missing.

A successful /health response proves only that the Worker is running, not that Activepieces is reachable.
