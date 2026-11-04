# SentinelX Fixed LLM Agent and Multi-Tenant Tool Architecture

Status: fixed platform-agent implementation deployed. OpenRouter API key configuration and live inference test require the platform administrator to enter the platform key in the GUI.

## Product contract

SentinelX has one centrally managed defensive SOC agent and one fixed model for every customer workspace. Customers configure their own security tools, not their own agent or model.

- **BYO-Security-Tools:** each workspace/user connects the tools they own or are authorized to access. The agent sees only the authenticated user's connected, query-capable tools.
- **Fixed SentinelX Agent:** `SentinelX SOC Investigator v1` has centrally managed identity, system policy, planning loop and tool-selection guardrails.
- **Fixed LLM:** OpenRouter model `nvidia/nemotron-3-ultra:free`. Customers cannot select providers, models, endpoints, fallbacks or agent profiles.
- **Platform API key:** a SentinelX platform administrator configures one shared OpenRouter API key in Settings → Integration settings. The key is encrypted at rest using AES-GCM and is never returned to the browser.
- **Platform administrator authorization:** D1 `platform_admins` allowlist. Migration `0007_platform_admins.sql` bootstraps the existing owner(s) at migration time; future tenant owners are not automatically platform administrators.
- **No fake verification:** model configured, provider test passed, agent run completed and connected tool verified are separate states.

The selected NVIDIA Nemotron 3 Ultra `:free` variant is listed at $0 input/output token pricing on OpenRouter. Free-tier capacity, rate limits and availability can change. All requests use the shared SentinelX platform API key.

## Target architecture

```text
Customer GUI
  | authenticated tenant session + investigation prompt
  v
Cloudflare Worker — identity, policy and agent runtime
  |-- fixed SentinelX SOC Investigator v1
  |-- fixed OpenRouter model + platform-owned API key
  |-- tenant/user-scoped connected-tool catalog
  |-- server-side tool schema validation
  |-- per-run and per-tool audit trail
  |
  +--> only the authenticated user's connected read-only tools
         |--> Wazuh
         |--> VirusTotal / AbuseIPDB / URLScan
         |--> Sysmon / Suricata / Zeek collector telemetry
         |--> ClamAV / YARA results
```

ActivePieces remains the workflow orchestration engine. It does not control model selection and does not receive the shared OpenRouter API key.

## Fixed model configuration

- Provider endpoint: `https://openrouter.ai/api/v1/chat/completions`
- Model ID: `nvidia/nemotron-3-ultra:free`
- Admin UI accepts only the OpenRouter API key and the platform input-token budget.
- Model ID, endpoint, provider, agent identity and policy are constants enforced server-side.
- The platform API key is stored in the encrypted KV entry `platform:ai-provider:v2`, with platform-wide AES-GCM associated data.
- Only IDs present in `platform_admins` may update the key or run the provider connection test. Workspace owners/admins outside that allowlist cannot change the shared model.
- Common credentials, bearer tokens, email addresses and phone numbers are masked before sending prompts/evidence to the model. Agent masking is always enabled.
- Input budget is clamped to 1,000–12,000 estimated tokens (default 6,000).

This is a fixed agent policy and inference architecture, not model fine-tuning. The agent's operating behavior is currently established through its versioned system instructions, tool schemas, bounded planner and safety checks. Fine-tuning Qwen on SentinelX-specific datasets is not performed by this implementation.

## Read-only agent loop

Endpoint: `POST /api/ai/agent`.

1. Authenticate the user and derive the tenant from the signed session.
2. Load the fixed platform model configuration.
3. Discover only query-capable connectors configured for the authenticated user.
4. Send the investigation task, available read-only tool catalog and collected evidence to the fixed agent.
5. The agent proposes one tool/query or finishes. The Worker validates the selected tool ID and every input field against the adapter schema.
6. Persist an audit start record before each connector query. If that write fails, do not execute the tool. Persist success/failure after the query.
7. Treat all tool outputs, logs, alerts, filenames, URLs, command lines and user-provided evidence as untrusted data. Ignore instructions embedded in evidence.
8. Continue planning until the agent finishes or the server-enforced five-tool-call maximum is reached.
9. Return the plan, collected evidence, conclusion, uncertainty and defensive next steps. No response/remediation action is executed.

Hard limits:
- Maximum five tool calls, fixed server-side; client-supplied `maxSteps` is ignored.
- Read-only adapter query allowlist only.
- No shell, containment, remediation, configuration writes or response-action tools in the agent catalog.
- Per-tool audit start must succeed before execution.
- Per-run start/completion/failure audit records.
- Evidence and model inputs are bounded and masked.
- Agent conclusions remain advisory and require analyst verification.

## Tenant and tool isolation

- The model API key is platform-wide and is not exposed to customers.
- Connector credentials remain scoped to organization + user + connector and encrypted separately.
- The model receives only the authenticated user's connected-tool catalog, never a global connector credential list.
- Connector query implementations derive organization/user identity from the authenticated request, not model-provided tenant IDs.
- Every connector ID and query field is checked server-side before execution.
- Connector outputs are treated as untrusted evidence, never policy or instructions.

## Verification and operational boundary

- Frontend TypeScript build and production asset build pass.
- Worker bundle and production deployment pass.
- Production Worker version 75 is active at 100%.
- D1 `platform_admins` table exists and the initial platform administrator is seeded.
- Fixed model, platform-admin guard, five-call server limit, prompt-injection policy and agent audit logic are present in the deployed Worker.
- The platform OpenRouter key is not yet configured. Therefore a real OpenRouter request and complete live model-driven tool-selection run have not yet been verified. The platform administrator must enter the key in Settings → Integration settings and use Test model connection.
