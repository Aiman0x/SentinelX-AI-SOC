# SentinelX Cloudflare Worker — GUI + API Gateway

The `sentinelx-api-gateway` Worker serves both the React GUI static assets and the authenticated API gateway. The browser and API share one origin; the Worker forwards authenticated read requests to the existing ActivePieces workflows.

## Public origin

`https://sentinelx-api-gateway.aiman132046.workers.dev`

## Security model

- The GUI authenticates with a dedicated analyst password sent only to `POST /api/auth/login`.
- The Worker verifies a PBKDF2-SHA-256 password hash; the plaintext password is never stored in Worker configuration.
- Successful login receives a four-hour signed, HttpOnly, Secure, same-site session cookie.
- Session signatures use a separate `SESSION_HMAC_SECRET` Worker secret.
- Login attempts are rate-limited (5 per minute per IP; Cloudflare's rate limiter is approximate).
- ActivePieces bridge key remains a Worker secret and is never sent to the browser.
- Data retrieval is GET-only. The only write endpoint in this phase saves encrypted integration configuration; case updates, playbook execution, connection tests, and defensive actions are not exposed.
- This is a single shared analyst login, not multi-user identity management. Use a unique, strong password and rotate it if shared.

## Authentication endpoints

- `POST /api/auth/login` with JSON `{"password":"..."}` sets the session cookie.
- `GET /api/auth/me` reports whether the cookie is valid.
- `POST /api/auth/logout` clears the cookie.

The GUI is served by the same Worker origin as the API, so browser requests use same-origin cookies and do not need a cross-site cookie exception.

## Worker variables and secrets

The Worker origin is configured in `cloudflare-worker/wrangler.toml`:

- `ALLOWED_ORIGIN` = `https://sentinelx-api-gateway.aiman132046.workers.dev`

Add these as **Secret** values in Workers & Pages > sentinelx-api-gateway > Settings > Variables and Secrets:

- `LOGIN_PASSWORD_HASH` = PBKDF2-SHA-256 encoded hash in the format `pbkdf2-sha256$310000$BASE64URL_SALT$BASE64URL_HASH`
- `SESSION_HMAC_SECRET` = a separately generated random secret (at least 32 random bytes, encoded as hex)
- `CONFIG_ENCRYPTION_KEY` = a separate 32-byte random AES-256-GCM key (64 hex characters)
- `AP_BRIDGE_KEY` = the rotated `X-SentinelX-Bridge-Key` value configured on all eight ActivePieces read workflows
- `AP_READ_DETECTION_FINDINGS_URL`, `AP_READ_INCIDENT_RECORDS_URL`, `AP_READ_INVESTIGATIONS_URL`, `AP_READ_EVIDENCE_REFERENCES_URL`, `AP_READ_AUDIT_LOGS_URL`, `AP_READ_ASSETS_URL`, `AP_READ_DETECTION_RULES_URL`, and `AP_READ_SECURITY_INTEGRATIONS_URL` = corresponding published ActivePieces webhook URLs with `/sync` appended

Do not reuse the Windows telemetry-ingestion key. Do not put any secret or ActivePieces webhook URL in GitHub source, Vite variables, or browser code. The `INTEGRATION_CONFIGS` KV namespace stores tool configuration encrypted with AES-256-GCM; the encryption key stays in Worker Secrets. Secret fields are never returned to the browser.

Copy each webhook URL from its corresponding published ActivePieces workflow trigger, then append `/sync` to the URL path so the Worker waits for the flow's Return Response step. The Catch Webhook trigger accepts GET, and each flow's Return Response step returns the table data as JSON. Confirm its auth check expects the bridge key header before enabling live data. Do not guess URLs.

## Integration configuration

- `POST /api/integrations/{id}/config` saves allowlisted configuration fields after analyst authentication.
- Supported IDs: wazuh, sysmon, clamav, yara, suricata, zeek. ActivePieces webhook URLs and bridge credentials are configured only as Worker Secrets.
- Values are encrypted before being written to the dedicated `INTEGRATION_CONFIGS` KV namespace.
- `GET /api/integrations` includes only safe non-secret configuration values and configured field names; passwords and webhook secrets are never returned.
- Connection-test routes deliberately return an unavailable response until each tool-specific ActivePieces adapter and health-check workflow is implemented. A saved configuration is not a connected integration.

## Read-only route mapping

| Frontend route | ActivePieces workflow |
|---|---|
| GET /api/alerts | Read Detection Findings |
| GET /api/cases | Read Incident Records |
| GET /api/investigations | Read Investigations |
| GET /api/evidence | Read Evidence References |
| GET /api/audit | Read Audit Logs |
| GET /api/assets | Read Assets |
| GET /api/rules | Read Detection Rules |
| GET /api/integrations | Read Security Integrations |

## Deployment

The repository's `.github/workflows/deploy-worker.yml` builds the React GUI and deploys the GUI assets plus API Worker together. The Worker uses Workers Static Assets with SPA fallback; `/api/*` requests are routed through the Worker code.

### GitHub Actions prerequisite

- Add `CLOUDFLARE_API_TOKEN` as a GitHub Actions secret. Grant only the Cloudflare permissions needed to deploy Workers Scripts.

### Runtime configuration

1. Run `scripts/generate-auth-secrets.ps1` locally and add its outputs as Worker Secrets. Choose the analyst password locally; it is never sent to GitHub or this repository.
2. Rotate the shared bridge credential on all eight ActivePieces read workflows, then set the matching value as `AP_BRIDGE_KEY` in Worker Secrets.
3. Add the eight ActivePieces webhook URL secrets copied from their published trigger settings, with `/sync` appended.
4. Add the generated `LOGIN_PASSWORD_HASH`, `SESSION_HMAC_SECRET`, and `CONFIG_ENCRYPTION_KEY` as Worker Secrets.
5. Merge the deployment branch into `main`; the GitHub Actions workflow builds the GUI and deploys the combined Worker.
6. Open the public Worker origin above and verify login and the read-only GUI routes after runtime secrets are configured.

A successful `/health` endpoint is intentionally not provided: only the authentication and actual data endpoints should be used to validate the deployed gateway.
