# SentinelX — AI-Assisted Security Operations Center

SentinelX is a defensive SOC capstone project focused on authorized telemetry ingestion, detection, investigation, evidence handling, and analyst-guided response.

The intended design uses **ActivePieces as the primary workflow/orchestration backend**, a **Cloudflare Worker API gateway** for authenticated GUI access, and a **React + TypeScript** analyst interface.

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
Cloudflare Worker API gateway
  - analyst password login and signed session
  - authenticated read routes
  - encrypted integration configuration storage
        ^
        |
React + TypeScript SOC GUI (GitHub Pages)
```

The GUI/backend foundation is being developed on the `feat/cloudflare-api-gateway` branch and tracked in [PR #12](https://github.com/Aiman0x/SentinelX-AI-SOC/pull/12). The Worker is **not deployed** and GitHub Pages has **not yet been configured** to use it. Until deployment and secure configuration are complete, the public GUI remains in demo mode.

## Implemented in the foundation branch

- Dark black/red/gold SOC GUI with alerts, cases, investigations, assets, integrations, detection rules, playbooks, audit logs, and settings.
- Backend-aware GUI data loaders and mappers for alerts, cases, investigations, evidence references, assets, rules, audit logs, and integrations.
- Cloudflare Worker source with PBKDF2 analyst-password verification, signed HttpOnly session cookies, login rate limiting, and origin-restricted credentialed CORS.
- Authenticated read routes from the GUI through ActivePieces read workflows.
- Encrypted integration-configuration endpoint using AES-256-GCM and a dedicated Workers KV namespace. Secrets are not returned to the browser.
- Read-only GUI states where case, asset, and detection-rule write APIs are not yet available.
- Clear labels for sample trend charts and correlation findings that are not AI verdicts.

## Workflow validation

The eight GUI read workflows and selected core telemetry/detection workflows have passed ActivePieces structural validation. This confirms workflow configuration only; it does **not** prove live GUI-to-backend connectivity, real Windows-event processing, tool connectivity, or AI-model operation.

## Still pending

- Deploy the Cloudflare Worker and securely configure its secrets and actual ActivePieces webhook URLs.
- Rotate the shared GUI bridge credential before deployment; it is separate from the telemetry-ingestion key.
- Set the GitHub Pages repository variable `VITE_API_BASE_URL` only after the Worker is deployed and its session behavior is verified.
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

**Status: In Development — GUI/backend foundation under construction.**
