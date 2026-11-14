# SentinelX Windows Endpoint Collector

The Windows collector is a read-only PowerShell script. It reads selected Windows Security and Sysmon Event Log records and sends them to the tenant-scoped SentinelX Worker over outbound HTTPS. It does not install Sysmon, change audit policy, block traffic, quarantine files, or execute response actions.

## Enroll and start

1. Sign in to SentinelX as an owner or admin.
2. Open **Tools → Windows Hosts** and enroll the Windows PC.
3. Copy the one-time setup command shown by SentinelX.
4. Open PowerShell as Administrator on that Windows PC and paste the command.
5. Keep the PowerShell window running for continuous collection. Press **Ctrl+C** to stop.

The command downloads the current collector script from this repository, sets the one-time token in the current PowerShell process, and starts continuous collection. The token is stored only as a SHA-256 hash in D1; it is never shown again after the enrollment panel is closed. Do not share the command because it contains the token.

## Collected Windows Security events

| Event ID | Meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4688 | Process creation |
| 4697 | Service installed |
| 4720 | User account created |
| 4728 / 4732 | User added to a security group |
| 1102 | Security audit log cleared |

## Collected Sysmon events

When Sysmon is installed and its Event Log channel is readable, the collector also reads:
- 1 process creation
- 3 network connection
- 7 image loaded
- 10 process access
- 11 file created
- 12/13 registry object or value change
- 22 DNS query
- 23/26 file deletion

Sysmon is optional. If the channel is unavailable, Windows Security collection continues. Install and configure Sysmon separately using an approved configuration; SentinelX does not silently install or reconfigure endpoint software.

## How data moves

1. The collector authenticates using its enrolled Bearer token.
2. The Worker validates the token, organization and pause/revocation state.
3. Events are normalized and queued.
4. The queue consumer stores events in the tenant-scoped `security_events` table.
5. The detection engine evaluates each event and creates incidents/evidence when rules match.
6. The AI agent can query the Windows Security and Sysmon read-only tools from its tool catalog.

Each channel has a separate local checkpoint under `%LOCALAPPDATA%\SentinelX`. A checkpoint advances only after SentinelX confirms event acceptance. Repeated submissions are deduplicated by organization, source and Windows event identity.

## Manage the endpoint

- **Pause:** SentinelX rejects further event submissions while paused.
- **Resume:** collection resumes on the next polling cycle.
- **Stop:** press Ctrl+C in the PowerShell window.
- **Revoke:** permanently invalidates the collector token. Enroll a new collector to reconnect.

## Troubleshooting

- **401:** token is invalid, revoked, or copied incorrectly.
- **423:** collector is paused in SentinelX.
- **Sysmon not available:** the Security channel still works; Sysmon events require Sysmon to be installed and enabled.
- **No recent telemetry:** keep the PowerShell process running and check the host's Security log permissions and network access to the SentinelX HTTPS gateway.
- **No detections:** event ingestion and detection are separate; an event can be stored without matching a detection rule.

The collector uses outbound HTTPS only. Do not expose Windows Event Log, Wazuh API, or host administration ports to the public internet.
