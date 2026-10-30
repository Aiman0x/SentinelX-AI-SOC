# SentinelX — Setup Guide

## 1. Purpose

This guide covers the current GUI/backend foundation. SentinelX is still under development; completing these setup steps does not by itself prove real telemetry or AI functionality.

## 2. GUI development

Requirements: Node.js 18+ and npm.

```bash
npm install
npm run dev
npm run build
npm run preview
```

Without `VITE_API_BASE_URL`, the GUI runs in clearly labelled demo mode.

## 3. ActivePieces

ActivePieces is the primary workflow engine. The eight GUI read workflows use authenticated Catch Webhook triggers and Return Response steps. The Cloudflare Worker must call the published webhook URL with `/sync` appended so it receives the Return Response payload.

Copy the actual published webhook URLs from ActivePieces; do not guess or construct them. Treat these URLs as secrets.

The eight GUI read workflows and selected core telemetry/detection flows have passed structural validation. Do not treat this as a real-event test.

## 4. Cloudflare Worker foundation

Worker source and configuration are in `cloudflare-worker/`.

The foundation uses:
- analyst password verification and signed HttpOnly session cookies;
- login rate limiting;
- CORS restricted to the SentinelX GitHub Pages origin;
- server-side ActivePieces webhook secrets;
- a dedicated Workers KV namespace for AES-256-GCM encrypted integration configuration.

Before deployment, the bridge key must be rotated across all eight ActivePieces read workflows. It is separate from the Windows telemetry intake key.

Run `cloudflare-worker/scripts/generate-auth-secrets.ps1` locally to generate the analyst password hash, session signing secret, and configuration encryption key. Add each output directly to the matching Cloudflare Worker Secret. Never paste these values into chat, GitHub source, or the frontend.

Configure the eight actual ActivePieces webhook URLs as Worker Secrets and append `/sync` to each published URL. Set `ALLOWED_ORIGIN` to `https://aiman0x.github.io`.

The Worker is not deployed yet. Do not set `VITE_API_BASE_URL` until the Worker has been deployed and its login/session behavior is verified.

## 5. Integration configuration

The GUI can submit allowlisted tool configuration to the authenticated Worker endpoint. The Worker encrypts values before saving them to the dedicated KV namespace. Secret values are not returned to the browser.

A saved configuration is not a connected integration. Tool-specific ActivePieces adapters and health-check workflows must be completed before connection status can be verified.

## 6. Security and testing

- Never store passwords, API keys, bridge credentials, webhook URLs, or encryption keys in source control.
- Do not reuse the telemetry ingestion key as the GUI bridge key.
- Use only authorized telemetry sources and systems.
- Keep case/rule/asset writes and disruptive response actions disabled until their server-side APIs and approval/audit controls are ready.
- Real Windows-event, remote telemetry, and AI-model tests are deferred until the GUI/backend foundation is configured.

## 7. Current limitations

- The Worker is not deployed.
- The GUI is not connected to the deployed Worker.
- Case, asset, and detection-rule write APIs are not available.
- Wazuh, Sysmon, Suricata, Zeek, ClamAV, and YARA connection adapters are pending.
- AI investigation and real-event end-to-end validation are pending.
