# SentinelX — AI-Assisted Security Operations Center

SentinelX is a defensive SOC capstone project focused on authorized telemetry ingestion, detection, investigation, evidence handling, and analyst-guided response.

The intended design uses **ActivePieces as the primary workflow/orchestration backend**, and a **Cloudflare Worker** to serve the React GUI and securely proxy authenticated API requests to ActivePieces.

## Current architecture

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

The GUI and API gateway are deployed together at:

`https://sentinelx-api-gateway.aiman132046.workers.dev`

The source and deployment foundation are maintained on `feat/cloudflare-api-gateway` and tracked in [PR #12](https://github.com/Aiman0x/SentinelX-AI-SOC/pull/12). Deployment is not complete until the branch is merged, GitHub Actions credentials are configured, and Worker runtime secrets are added.

## Implemented in the foundation branch

- Dark black/red/gold SOC GUI with alerts, cases, investigations, assets, integrations, detection rules, playbooks, audit logs, and settings.
- Backend-aware GUI data loaders and mappers for alerts, cases, investigations, evidence references, assets, rules, audit logs, and integrations.
- Cloudflare Worker source with PBKDF2 analyst-password verification, signed HttpOnly session cookies, login rate limiting, and origin-restricted credentialed CORS.
- Authenticated read routes from the GUI through ActivePieces read workflows.
- Encrypted integration-configuration endpoint using AES-256-GCM and a dedicated Workers KV namespace. Secrets are not returned to the browser.
- Read-only GUI states where case, asset, and detection-rule write APIs are not yet available.
- Clear labels for sample trend charts and correlation findings that are not AI verdicts.
- Workers Static Assets configuration to serve the GUI and route `/api/*` requests through the same Worker origin.

## ActivePieces status

The eight GUI read workflows are already present and enabled. Structural validation confirms workflow configuration only; it does **not** prove live GUI-to-backend connectivity, real Windows-event processing, tool connectivity, or AI-model operation.

## Deployment prerequisites

- Merge the foundation branch/PR into `main`.
- Add `CLOUDFLARE_API_TOKEN` as a GitHub Actions secret with permission to deploy Workers Scripts.
- Add `CLOUDFLARE_ACCOUNT_ID` as a GitHub Actions repository/environment variable.
- Add the Worker runtime secrets documented in `cloudflare-worker/README.md`.
- Rotate the GUI bridge credential on all eight ActivePieces read workflows before connecting production data.
- Configure the eight published ActivePieces webhook URLs as Worker Secrets.
- Generate the analyst password hash locally using `cloudflare-worker/scripts/generate-auth-secrets.ps1`; never commit the generated values.

## Still pending

- Merge and deploy the Cloudflare Worker with GUI assets.
- Configure and verify Worker secrets and ActivePieces webhook URLs.
- Implement case, asset, and detection-rule write APIs.
- Build tool-specific adapters and health checks for Wazuh, Sysmon, Suricata, Zeek, ClamAV, and YARA.
- Connect and verify an AI investigation model.
- Perform real Windows and authorized remote telemetry validation only after the GUI/backend foundation is configured.
- Add audited, human-approved defensive response workflows.

## Run the GUI locally

Requirements: Node.js 18+ and npm.

```bash
npm install
npm run dev
npm run build
npm run preview
```

Without `VITE_API_BASE_URL`, the GUI uses demo data. Never put secrets in `VITE_*` variables or frontend source.

## Security principles

- Use SentinelX only with systems and data you are authorized to monitor.
- Never commit API keys, webhook URLs, bridge keys, passwords, or encryption keys.
- Keep credentials in server-side secret storage and encrypt integration secrets before persistence.
- Do not describe demo data, saved configurations, or structurally valid workflows as verified telemetry or connected tools.
- Keep disruptive response actions disabled until authentication, approval, and audit controls are implemented.

**Status: In Development — unified Workers deployment foundation prepared; runtime configuration and deployment remain pending.**
