# SentinelX — AI-Assisted Security Operations Center

SentinelX is a defensive SOC capstone project focused on authorized telemetry ingestion, detection, investigation, evidence handling, and analyst-guided response.

The intended design uses **ActivePieces as the primary workflow/orchestration backend**, and a **Cloudflare Worker** to serve the React GUI and securely proxy authenticated API requests to ActivePieces.

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
- Authenticated read routes from the GUI through the existing ActivePieces read workflows.
- Encrypted integration-configuration endpoint using AES-256-GCM and a dedicated Workers KV namespace.
- Workers Static Assets configuration to serve the GUI and route `/api/*` requests through the same Worker origin.

## ActivePieces status

Eight GUI read workflows already exist and are enabled. This confirms workflow configuration only; it does **not** prove live GUI-to-backend connectivity, real Windows-event processing, tool connectivity, or AI-model operation.

## Deployment prerequisites

- Add `CLOUDFLARE_API_TOKEN` as a GitHub Actions secret with permission to deploy Workers Scripts.
- Generate the analyst password hash, session HMAC secret, and AES encryption key locally.
- Rotate the shared GUI bridge credential on all eight ActivePieces read workflows.
- Configure the eight published ActivePieces webhook URLs as Worker Secrets.

See `cloudflare-worker/README.md` for the exact runtime secret names and setup instructions.

## Still pending

- Deploy and verify the combined Cloudflare Worker.
- Configure Worker secrets and ActivePieces webhook URLs.
- Implement case, asset, and detection-rule write APIs.
- Build tool-specific adapters and health checks for Wazuh, Sysmon, Suricata, Zeek, ClamAV, and YARA.
- Connect and verify an AI investigation model.
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

## Security principles

- Use SentinelX only with systems and data you are authorized to monitor.
- Never commit API keys, webhook URLs, bridge keys, passwords, or encryption keys.
- Keep credentials in server-side secret storage and encrypt integration secrets before persistence.
- Do not describe demo data, saved configurations, or structurally valid workflows as verified telemetry or connected tools.
- Keep disruptive response actions disabled until authentication, approval, and audit controls are implemented.

**Status: In Development — unified Workers deployment prepared; runtime configuration and deployment remain pending.**
