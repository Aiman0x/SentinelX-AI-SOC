# SentinelX BYO-LLM and Multi-Tenant Integration Architecture

Status: implementation blueprint. This document does not claim that provider calls or adapters are already implemented.

## Product contract

SentinelX is a multi-tenant AI SOC platform. It must not depend on the maintainer's Wazuh server, Azure VM, ActivePieces account, or model account. Each workspace connects its own tools and chooses its own model provider.

- **BYO-Security-Tools:** a workspace may connect zero or more supported tools. Wazuh is optional, not a platform prerequisite.
- **BYO-LLM:** a workspace may configure its own provider, API key, model, endpoint (where supported), and analysis preferences.
- **No shared credentials:** credentials and connection state are scoped to a workspace and never shared between tenants.
- **No fake verification:** saved, reachable, telemetry observed, and verified are separate states.
- **Graceful optionality:** missing integrations reduce available evidence; they must not prevent the platform from operating with other connected sources.

## Target architecture

```text
Browser GUI
  | authenticated workspace session
  v
Cloudflare Worker — control plane / policy enforcement
  |-- workspace identity and role checks
  |-- encrypted, tenant-scoped integration/provider secrets
  |-- connector registry and health state
  |-- normalized event and investigation APIs
  |
  +--> ActivePieces — optional workflow orchestration
  |      |--> connector-specific intake/processing flows
  |      +--> normalized events, cases and audit records
  |
  +--> LLM Provider Adapter
         |--> OpenAI-compatible APIs
         |--> Anthropic API
         |--> Google Gemini API
         |--> self-hosted OpenAI-compatible endpoint (e.g. Ollama/vLLM)
```

ActivePieces remains reusable as an orchestration engine, but it is not the identity system and must not hold a single global provider/tool credential for all customers. A future deployment may replace or supplement it without changing the GUI's connector contracts.

## BYO-LLM workspace settings

A provider profile contains:
- provider identifier and display name
- API base URL only for providers that support custom endpoints
- model identifier
- secret reference (never the raw API key in browser state)
- optional organization/project identifier when required by the provider
- enabled capabilities: chat, structured output, tool calling (only when supported)
- timeout, output-token limit, and optional per-workspace budget/rate limits
- last test timestamp, status, and a redacted diagnostic

Required UX:
1. Choose provider.
2. Enter model and API key; custom endpoint is optional and validated.
3. Save encrypted server-side.
4. Test connection with a minimal, non-sensitive request.
5. Select the active model for investigation and report generation.
6. Allow update, disable, delete, and rotate without exposing the stored key.

The UI may display a masked placeholder such as `••••••••`; it must never retrieve the original key. Never put provider secrets in Vite environment variables, localStorage, logs, analytics, URLs, or ActivePieces flow definitions.

## Provider adapter contract

All providers implement one internal interface:
- `validateConfig(config)`
- `testConnection(secretRef, config)`
- `generateAnalysis(request, secretRef, config)`

The normalized result includes provider/model identifiers, response text, structured findings when supported, usage metadata when available, duration, and a redacted error. Provider-specific SDKs and payloads stay behind the adapter. Never assume all providers support tool calling or JSON schema; capability flags must be explicit.

Use server-side requests only. Validate endpoint schemes and destinations to prevent SSRF; block loopback, link-local, private, and metadata IP ranges for user-supplied hosted endpoints unless an explicitly approved self-hosted connector mode is implemented. Apply timeouts, response-size limits, rate limits, and per-workspace quotas. Do not silently fall back to another provider or transmit telemetry to a different provider without workspace consent.

## Security-tool connector contract

Each connector has:
- stable `integrationId`, version, category, and capability declarations
- tenant-scoped configuration schema (public fields and secret fields distinguished)
- setup instructions and prerequisites
- `testConnection` and `getHealth`
- inbound webhook and/or outbound polling/collector mode as appropriate
- conversion to SentinelX's normalized event schema
- explicit permissions and read-only defaults

Initial connector catalog (optional, not assumed installed):
- Wazuh
- Windows Event Log / Sysmon via a local collector
- Suricata
- Zeek
- ClamAV
- YARA
- ActivePieces as an orchestration connector

A tool is not a generic plugin merely because a user can type its URL. Every connector requires a tested adapter. Do not expose management ports (for example Wazuh API 55000 or clamd 3310) to the public internet. Prefer outbound, device-authenticated HTTPS collectors or private network connectivity.

## Tenant isolation and data model

Every workspace-owned record must carry an immutable `org_id`: integration configs, provider profiles, sensors, events, alerts, cases, investigations, evidence, playbooks, and audit entries. Every read/write query and webhook lookup must enforce the authenticated workspace scope server-side. Never trust a workspace ID supplied only by the browser.

Secret encryption must use authenticated encryption with key versioning and tenant-bound associated data. Store ciphertext and a secret reference; never store plaintext secrets in KV, logs, workflow payloads, or frontend responses. Rotate encryption keys with a migration path. Audit create/update/test/disable/delete events without recording secret values.

## Investigation pipeline

1. Receive telemetry from connected sources.
2. Authenticate source identity and enforce tenant ownership.
3. Validate and normalize event shape; preserve source, sensor, timestamp, and evidence references.
4. Deduplicate and correlate events across tools.
5. Build a bounded investigation context with provenance and timestamps.
6. Send only the necessary context to the workspace-selected LLM provider.
7. Treat model output as analysis, not truth: separate observed facts, hypotheses, confidence, gaps, and recommended next steps.
8. Require analyst approval for disruptive actions; record the decision and evidence in the audit trail.

The LLM must not invent telemetry, claim an integration is connected based on saved configuration, or perform destructive response actions autonomously.

## Migration from the current prototype

Keep and reuse:
- React SOC GUI and dark theme
- Cloudflare Worker authentication/session controls
- encrypted configuration storage (after tenant scoping and key review)
- existing ActivePieces workflows where they can be made workspace-aware
- common alert/case/investigation UI and adapter contract

Refactor:
- fixed/default Wazuh assumptions into an optional Wazuh connector
- global integration IDs/config lookups into workspace-scoped records
- demo-only AI assistant into a server-side provider adapter with clear demo/live labels
- ActivePieces credentials and webhook routing into per-workspace authorization boundaries

Do not delete the Windows collector or existing Wazuh setup scripts: they remain useful as one optional reference connector and a test fixture. Do not remove authentication, audit, evidence, or approval controls.

## Delivery order

1. Tenant-scoped data and integration configuration boundary.
2. BYO-LLM provider profile API, encrypted secret lifecycle, and connection test.
3. Provider adapter and investigation endpoint; connect the Analyst Assistant.
4. GUI provider setup and active-model selection.
5. Connector registry and generic add/configure/test/disable UX.
6. Refactor Wazuh as the first optional connector; verify one real workspace end-to-end.
7. Add other adapters incrementally, each with functional and telemetry tests.

## Acceptance criteria

- A new workspace can use SentinelX without connecting Wazuh.
- Two workspaces can connect different Wazuh servers and different LLM providers without cross-visibility.
- A workspace can use BYO-LLM without any local model running on the SentinelX host.
- API keys are never returned to the browser after save.
- Connection tests are real provider/tool tests, not placeholder success.
- The Analyst Assistant clearly distinguishes live model analysis from demo/template output.
- No telemetry is sent to an unselected provider.
- Existing read-only and human-approval safeguards remain enforced.
