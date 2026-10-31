# SentinelX Windows telemetry connection

## What is included

- scripts/SentinelX_Local_Windows_Collector.ps1 reads Windows Security Event ID 4625 only.
- It extracts named XML event fields and sends read-only telemetry to the configured intake webhook.
- It checkpoints the last successfully accepted Windows record ID under %LOCALAPPDATA%\SentinelX\.
- scripts/SentinelX_Local_Agent.ps1 exposes a loopback-only control API so the GUI can start and stop the collector.
- /telemetry displays received events and collector status. Raw telemetry is not automatically promoted to confirmed alerts.

## One-time local agent startup

A browser cannot read the Windows Security log or launch local processes by itself. The local agent is the small, explicit bridge required for those OS permissions. Start it once on the Windows PC; after that, use Start collector and Stop collector in the GUI.

Open an elevated PowerShell window in the repository's scripts directory. The intake URL and key must already be available as environment variables in that session; do not paste them into the GUI or commit them.

    Set-ExecutionPolicy -Scope Process Bypass
    .\SentinelX_Local_Agent.ps1

The agent binds only to 127.0.0.1:8765, allows the configured SentinelX GUI origin only, and requires a custom request header. It does not listen on the LAN. The default GUI origin is https://sentinelx-api-gateway.aiman132046.workers.dev. For local Vite development, pass the exact local origin, for example -AllowedOrigin http://localhost:5173.

Keep the agent PowerShell window open while using the GUI. Close it with Ctrl+C when finished. The GUI start/stop controls manage only the collector child process; they do not shut down the local agent.

## Collector behavior and safety

- Reads Security Event ID 4625 (failed logons) only.
- Polls every 30 seconds by default.
- Does not create test logons, change Windows policy, disable security controls, or take response actions.
- Stop in the GUI terminates the collector process. The local agent itself remains running until Ctrl+C.
- Collector stdout/stderr logs are stored under %LOCALAPPDATA%\SentinelX\.

## Protected backend setting

The Cloudflare Worker read route uses AP_READ_WINDOWS_TELEMETRY_URL and the Activepieces read-flow trigger is protected by X-SentinelX-Bridge-Key. Store the matching bridge secret only in Activepieces and Cloudflare Worker secrets. Never put backend keys in the GUI, source code, wrangler configuration, or committed files.

## Data trust boundary

Local Windows events are tagged LOCAL_WINDOWS by the collector and normalized as REAL_UNVERIFIED. Keep them quarantined until host/source identity and event parsing have been validated. A raw telemetry row is not itself a confirmed incident or alert.
