# SentinelX Cloudflare API Gateway

Read-only gateway between the GitHub Pages frontend and the existing Activepieces GUI read workflows. This branch uses a small custom analyst login instead of Cloudflare Access, so it does not require a Zero Trust subscription or Access application.

## Security model

- The GUI authenticates with a dedicated analyst password sent only to `POST /api/auth/login`.
- The Worker verifies a PBKDF2-SHA-256 password hash; the plaintext password is never stored in Worker configuration.
- Successful login receives a four-hour signed, HttpOnly, Secure, SameSite=None, Partitioned session cookie.
- Session signatures use a separate `SESSION_HMAC_SECRET` Worker secret.
- Login attempts are rate-limited (5 per minute per IP and Cloudflare location; Cloudflare's rate limiter is approximate).
- CORS is restricted to `https://aiman0x.github.io` and credentialed requests only.
- Activepieces bridge key remains a Worker secret and is never sent to the browser.
- Only GET data routes are exposed. No case updates, playbook execution, or defensive actions are exposed in this phase.
- This is a single shared analyst login, not multi-user identity management. Use a unique, strong password and rotate it if shared.

## Authentication endpoints

- `POST /api/auth/login` with JSON `{"password":"..."}` sets the session cookie.
- `GET /api/auth/me` reports whether the cookie is valid.
- `POST /api/auth/logout` clears the cookie.

The browser must call the API with `credentials: "include"`. The cookie uses the Partitioned attribute because the GitHub Pages frontend and workers.dev API are on different sites. Browser third-party-cookie/privacy settings may still affect cookie behavior and must be checked during integration testing.

## Worker variables and secrets

Add these non-secret variables in Workers & Pages > sentinelx-api-gateway > Settings > Variables and Secrets:

- `ALLOWED_ORIGIN` = `https://aiman0x.github.io`
- `AP_READ_DETECTION_FINDINGS_URL`
- `AP_READ_INCIDENT_RECORDS_URL`
- `AP_READ_INVESTIGATIONS_URL`
- `AP_READ_EVIDENCE_REFERENCES_URL`
- `AP_READ_AUDIT_LOGS_URL`
- `AP_READ_ASSETS_URL`
- `AP_READ_DETECTION_RULES_URL`
- `AP_READ_SECURITY_INTEGRATIONS_URL`

Add these as **Secret** values, not plaintext variables:

- `LOGIN_PASSWORD_HASH` = PBKDF2-SHA-256 encoded hash in the format `pbkdf2-sha256$310000$BASE64URL_SALT$BASE64URL_HASH`
- `SESSION_HMAC_SECRET` = a separately generated random secret (at least 32 random bytes, encoded as hex)
- `AP_BRIDGE_KEY` = the rotated `X-SentinelX-Bridge-Key` value configured on all eight Activepieces read workflows

Do not reuse the telemetry ingestion key. Do not put any secret or Activepieces webhook URL in GitHub source, Vite variables, or browser code.

Copy each webhook URL from its corresponding published Activepieces workflow trigger. Confirm the trigger is GET and that its auth check expects the bridge key header before enabling live data. Do not guess URLs.

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

## Deployment

1. Add the variables and secrets above in the Cloudflare dashboard.
2. Deploy this Worker from the `feat/cloudflare-api-gateway` branch (or run `npx wrangler deploy` from this directory).
3. Update the frontend API client to use the Worker URL and `credentials: "include"`; implement login/logout and check `/api/auth/me`.
4. Verify actual Activepieces response shapes and map them to the frontend interfaces before enabling live dashboard data.

A successful `/health` endpoint is intentionally not provided: only the authentication and actual data endpoints should be used to validate the deployed gateway.
