# SentinelX — System Architecture

## 1. Overview

SentinelX is an AI-assisted defensive SOC platform under development. Its architecture separates telemetry ingestion, normalization, detection, correlation, investigation, evidence, tool configuration, and analyst-controlled response.

ActivePieces is the primary backend workflow/orchestration layer. A small Cloudflare Worker is being added as the authenticated API boundary between the React GUI and ActivePieces.

## 2. Current GUI/backend foundation

```text
React + TypeScript GUI (GitHub Pages)
        |
        | HTTPS, credentialed requests
        v
Cloudflare Worker API Gateway
  - analyst login / signed session
  - CORS and rate limiting
  - read-only data proxy
  - encrypted integration config API
        |                         |
        | GET /sync webhooks      | AES-256-GCM
        v                         v
ActivePieces workflows          Workers KV
        |
        v
SentinelX tables
```

The source for this foundation is on the `feat/cloudflare-api-gateway` branch. The Worker is not deployed and the GitHub Pages GUI has not yet been pointed at it. Until those setup steps are completed, the live GUI remains in demo mode.

## 3. ActivePieces workflows

The existing ActivePieces project contains:
- normalized telemetry intake and validation;
- duplicate checking and case creation;
- detection workflows;
- event correlation and investigation records;
- GUI read workflows for alerts, cases, investigations, evidence, audit logs, assets, rules, and integrations.

The eight GUI read workflows and selected core telemetry/detection workflows have passed structural validation. Structural validation is not a runtime test and does not verify real Windows events.

## 4. GUI data services

When `VITE_API_BASE_URL` is configured, the GUI requests data through the Worker. It does not hold ActivePieces webhook URLs, API keys, or tool passwords.

Backend-backed views currently include:
- alerts and alert details;
- cases (read-only);
- assets (read-only);
- detection rules (read-only);
- investigations/correlation records;
- audit records;
- integration registry and encrypted configuration.

Trend charts and response playbooks remain explicitly illustrative/demo content. Case, asset, and rule write operations are not enabled.

## 5. Integration configuration security

The Worker accepts allowlisted integration configuration only after analyst authentication. Configuration values are encrypted with AES-256-GCM before being stored in a dedicated Workers KV namespace. Passwords and webhook secrets are not returned to the browser.

Saving configuration does not establish connectivity. Tool-specific ActivePieces adapters and health-check workflows must be implemented before an integration can be marked connected.

## 6. Investigation and AI

Correlation records produced by ActivePieces are displayed as correlation findings and require analyst review. They are not represented as an autonomous AI verdict.

A verified AI investigation component is still pending. It must explain what happened, identify affected systems/accounts, distinguish evidence from assumptions, and recommend defensive next steps. Any future model integration must be tested against real, authorized telemetry before being described as operational.

## 7. Defensive response

Potentially disruptive actions must require explicit authorization, human approval, and audit logging. No real response action is exposed by this foundation.

## 8. Current implementation status

| Component | Status |
|---|---|
| ActivePieces telemetry intake | Configured; end-to-end real-event validation pending |
| Core detection/correlation workflows | Structurally valid; runtime verification pending |
| GUI read workflows | 8 workflows structurally valid |
| React GUI | Implemented; backend-aware loaders added |
| Cloudflare API gateway | Source scaffold and encrypted config storage added; not deployed |
| GUI-to-Worker authentication | Implemented in source; browser session not verified |
| Integration configuration | Encrypted save endpoint implemented; tool adapters pending |
| Wazuh/Sysmon/network tool connections | Pending |
| AI investigation model | Pending verification |
| Case/rule/asset write APIs | Pending |
| Real-event end-to-end testing | Deferred until GUI and backend foundation is configured |

## 9. Development sequence

1. Complete and validate GUI + backend foundation.
2. Configure and deploy the gateway securely.
3. Add tool adapters and verify connections.
4. Connect authorized Windows and remote telemetry.
5. Verify detection, correlation, and AI investigation against real events.
6. Add audited, approval-gated response workflows.
