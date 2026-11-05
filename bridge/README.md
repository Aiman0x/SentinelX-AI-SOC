# SentinelX Local Bridge

The bridge is a small outbound-only Go service for reaching tools that are installed on a customer's private LAN or workstation. It supports Windows, Linux and macOS from one codebase. No inbound firewall port and no Cloudflare Tunnel are required.

## Current implementation scope

- Secure HTTPS polling to the SentinelX Worker.
- Tenant-bound bridge token (the token is shown once by the enrollment API).
- Read-only Wazuh Manager agent/manager queries and Wazuh Indexer alert searches.
- Local or private HTTP/HTTPS Wazuh endpoints are contacted by the bridge, never by the Cloudflare Worker.
- Tool calls are queued per enrolled bridge and expire if not claimed in time.
- MCP transport is deliberately not advertised as active in this first bridge slice; the common MCP adapter will be added after the task transport and lifecycle are validated.

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
  "poll_ms": 1500
}
```

Run `sentinelx-bridge.exe -config sentinelx-bridge.json` on Windows, or `./sentinelx-bridge -config sentinelx-bridge.json` on Linux/macOS. Protect the config file with OS permissions. Do not commit it or share its token.

## Security boundaries

- Bridge token is stored server-side only as a SHA-256 hash and can be revoked.
- Requests are HTTPS outbound only; the bridge does not listen on a port.
- Only allowlisted read-only Wazuh operations are accepted in this build.
- No shell command execution, arbitrary URL forwarding, response actions, or write operations.
- Use a dedicated read-only Wazuh API and Indexer account.
- Never expose Wazuh Manager port 55000 or Indexer port 9200 to the public internet.
