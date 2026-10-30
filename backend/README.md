# SentinelX Backend Foundation

## Current architecture

SentinelX uses **ActivePieces as the primary workflow engine**. The browser does not call ActivePieces directly.

```text
React GUI (GitHub Pages)
        |
        | HTTPS + HttpOnly analyst session
        v
Cloudflare Worker API Gateway
        |                         |
        | authenticated reads     | AES-256-GCM encrypted config
        v                         v
ActivePieces read workflows     Workers KV
        |
        v
SentinelX tables
```

The Cloudflare Worker source and GUI integration are currently developed on the `feat/cloudflare-api-gateway` branch. The Worker is not deployed and the GUI is not yet configured to use it.

## Implemented in the foundation branch

- Password-based analyst login with PBKDF2 password verification, signed four-hour session cookies, and login rate limiting.
- Credentialed CORS restricted to the SentinelX GitHub Pages origin.
- Read routes for alerts, cases, investigations, evidence, audit records, assets, detection rules, and security integrations.
- Frontend data loaders and mappers for the current ActivePieces table schemas.
- Integration configuration save endpoint with allowlisted fields and AES-256-GCM encryption before Workers KV storage.
- Secrets remain server-side; the browser receives only non-secret configuration values and configured field names.
- Read-only controls in GUI sections where corresponding write APIs do not yet exist.

## Existing ActivePieces workflows

ActivePieces remains the primary orchestration layer. Workflows remain hosted in the ActivePieces project and are not stored in this repository.

The eight GUI read workflows and the core telemetry/detection workflows have passed ActivePieces structural validation. This validates workflow configuration only; it does not prove a live end-to-end request or real-event pipeline.

## Not yet implemented or verified

- Cloudflare Worker deployment and GUI-to-Worker browser session.
- Securely rotated bridge key and actual published webhook URLs configured as Worker Secrets.
- Case, asset, and detection-rule write APIs.
- Tool-specific Wazuh, Sysmon, Suricata, Zeek, ClamAV, and YARA adapters and real connection tests.
- A verified AI model investigation service.
- Real Windows/remote telemetry validation through the complete GUI-to-backend pipeline.
- Production response execution.

## Security requirements

- Never hardcode credentials or API keys.
- Keep all passwords, webhook URLs, bridge keys, session keys, and encryption keys in server-side secret storage.
- Encrypt integration credentials before persistence.
- Validate incoming data and restrict allowed integration fields.
- Do not log sensitive values.
- Keep response actions read-only until explicit authorization, audit, and approval controls are implemented.
