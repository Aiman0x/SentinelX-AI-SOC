# SentinelX Windows telemetry connection

## What is included

- `scripts/SentinelX_Local_Windows_Collector.ps1` reads Windows Security Event ID 4625 only.
- It extracts named XML event fields (target account, logon type, status/substatus, workstation, process, IP and record ID).
- It sends read-only telemetry to the existing Phase 3 Activepieces intake webhook.
- It checkpoints the last successfully accepted Windows record ID under `%LOCALAPPDATA%\SentinelX\`.
- `/telemetry` in the GUI reads the raw telemetry table; these rows are not automatically promoted to security alerts.

## Required protected connection setting

The Cloudflare Worker read route uses the following non-secret URL variable:

`AP_READ_WINDOWS_TELEMETRY_URL=https://cloud.activepieces.com/api/v1/webhooks/IGVyNQj1mZ0oX4EnqhH1l/sync`

The Activepieces read-flow trigger is protected by `X-SentinelX-Bridge-Key`. The exact same strong random value must be stored as:
- Activepieces flow trigger header value.
- Cloudflare Worker secret `AP_BRIDGE_KEY`.

Do not put this key in the GUI, source code, wrangler.toml, or a committed file. Rotate it if it is disclosed. The Cloudflare secret update is intentionally not committed as plaintext.

## Local collector setup (when deployment is ready)

In an elevated PowerShell window, set the existing intake URL and key in the current session, then run:

```powershell
$env:SENTINELX_WEBHOOK_URL = "YOUR_EXISTING_PHASE_3_INTAKE_WEBHOOK_URL"
$env:SENTINELX_WEBHOOK_KEY = "YOUR_EXISTING_INTAKE_KEY"
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\SentinelX_Local_Windows_Collector.ps1 -Continuous
```

The collector polls every 30 seconds by default. Use `Ctrl+C` to stop it. It does not create test logons, change Windows policy, or take response actions.

## Data trust boundary

Local Windows events are tagged `LOCAL_WINDOWS` by the collector and normalized as `REAL_UNVERIFIED`. Keep them quarantined until host/source identity and event parsing have been validated. A raw telemetry row is not itself a confirmed incident or alert.
