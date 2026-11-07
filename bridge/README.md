# SentinelX Local Bridge

The bridge is a small outbound-only Go service for reaching security tools from a customer's workstation or private network. It supports Windows, Linux and macOS from one codebase. No inbound firewall port and no Cloudflare Tunnel are required.

## Current implementation scope

- Secure HTTPS polling to the SentinelX Worker.
- Tenant-bound bridge token (the token is shown once by the enrollment API).
- Read-only Wazuh Manager agent/manager queries and Wazuh Indexer alert searches.
- MCP Streamable HTTP discovery and read-only tool calls through the same outbound bridge.
- MCP remote endpoints must use HTTPS. Plain HTTP is permitted only for localhost on the enrolled bridge machine (for example, `http://127.0.0.1:3000/mcp`).
- MCP private-LAN IP addresses and non-loopback local hostnames are blocked in this security phase. A future explicit per-endpoint network allowlist is needed before enabling those destinations safely.
- Local or private HTTP/HTTPS Wazuh endpoints are contacted by the bridge, never by the Cloudflare Worker.
- Tool calls are queued per enrolled bridge and expire if not claimed in time.
- MCP currently supports Streamable HTTP, paginated tool discovery (up to 1,000 tools), and bounded responses (512 KB per MCP response). Local stdio-launched MCP servers are not supported in this slice.

## Build

Install Go 1.22+ on a build machine, then run:

```sh
go build -trimpath -ldflags="-s -w" -o sentinelx-bridge .
```

Cross-compile:

```sh
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o sentinelx-bridge.exe .
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o sentinelx-bridge-linux .
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o sentinelx-bridge-macos .
```

Create a local `sentinelx-bridge.json` using the one-time enrollment token:

```json
{
  "gateway_url": "https://YOUR-SENTINELX-WORKER",
  "token": "ONE_TIME_DISPLAYED_TOKEN",
  "poll_ms": 1500,
  "ca_cert_file": "wazuh-ca.pem"
}
```

Run `sentinelx-bridge.exe -config sentinelx-bridge.json` on Windows, or `./sentinelx-bridge -config sentinelx-bridge.json` on Linux/macOS. If Wazuh uses a private certificate authority, provide its PEM CA path as `ca_cert_file`; TLS verification remains enabled. Protect the config file with OS permissions. Do not commit it or share its token.

## Security boundaries

- Bridge token is stored server-side only as a SHA-256 hash and can be revoked.
- Requests to SentinelX are HTTPS outbound only; the bridge does not listen on a port.
- MCP endpoint redirects are disabled; DNS results are checked at connection time to block private, loopback, link-local, reserved and metadata targets, with a localhost-only exception.
- Remote MCP bearer tokens are sent only over HTTPS. HTTP is allowed only to loopback services on the bridge machine.
- Only MCP tools advertising `annotations.readOnlyHint: true` can be called. This annotation is supplied by the MCP server and is not a cryptographic guarantee; connect only servers you trust and invoke tools deliberately.
- MCP server URLs and bearer tokens are supplied by an authenticated workspace user; bearer tokens are encrypted at rest and never returned to the browser.
- No shell command execution, arbitrary URL forwarding, response actions, or write operations are added by this connector.
- Use a dedicated read-only Wazuh API and Indexer account.
- Never expose Wazuh Manager port 55000 or Indexer port 9200 to the public internet.
