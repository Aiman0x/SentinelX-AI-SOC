# Windows Security and Sysmon Collector Ingestion Test

## Synthetic event contract

The collector sends flat events to `POST /api/collector/events` with:
- `Authorization: Bearer <collector-token>`
- `integrationId: windows_security` or `sysmon`
- `events: []`

Example Windows failed-logon event:

```json
{
  "integrationId": "windows_security",
  "events": [{
    "eventId": "win-security-test-host-12345",
    "eventType": "windows_failed_login",
    "observedAt": "2026-11-14T10:00:00.000Z",
    "host": "TEST-WIN",
    "username": "test-user",
    "sourceIp": "192.0.2.10",
    "severity": "medium",
    "message": "windows_failed_login | TargetUserName=test-user; IpAddress=192.0.2.10",
    "sourceIntegration": "Security",
    "dataOrigin": "LOCAL_WINDOWS",
    "eventData": { "EventID": 4625, "LogonType": "2", "RecordId": 12345 }
  }]
}
```

The backend also accepts the previous nested `{ payload: {...} }` envelope for compatibility. Normalization unwraps it while retaining a scrubbed copy of the original event.

## Expected pipeline behavior

1. A valid active collector token receives HTTP 202 with `accepted: 1` and `delivery: "queued"`.
2. Invalid/revoked tokens receive 401; paused collectors receive 423.
3. Events are queued and inserted into `security_events` with organization scope, source, event type, host, username, IPs, event data and timestamps.
4. Duplicate submissions from the same organization/source/event identity do not create duplicate rows.
5. The queue consumer invokes the detection engine after insertion.
6. Authenticated `GET /api/events` and `GET /api/telemetry` expose only the caller's organization data through their respective routes.
7. The AI read-only catalog exposes Windows Security and Sysmon tools when an active Windows collector is enrolled. Tool queries read from `security_events`, not the legacy `soc_records` table.
8. The Windows Security tool health test passes only when a recent event (under ten minutes old) has arrived.

## Local Windows validation

1. Enroll a Windows host in **Tools → Windows Hosts**.
2. Run the generated setup command in elevated PowerShell.
3. Confirm the console prints `Sent Security EventID ...` for available events. If Sysmon is installed, confirm Sysmon event lines as well.
4. Trigger a harmless failed sign-in on the test PC if you need a fresh 4625 event. Do not intentionally generate a large volume of failures.
5. Confirm the host shows online and the Windows Security tool's Test succeeds.
6. Confirm the event is visible in the SentinelX telemetry view and that the AI investigation can retrieve it.
7. Confirm the event's host, event type, username, source IP and event data are populated rather than generic `security_event`.

## Safety

- Never put collector tokens in URLs, source code, test fixtures, or logs.
- Use synthetic identities and documentation-only IPs in tests.
- The collector is read-only and does not modify audit policy, install Sysmon, or perform response actions.
- A successful HTTP 202 means queued, not yet persisted; verify the stored event and UI visibility before marking end-to-end PASS.
- Do not mark real Windows-host validation complete until the script has actually been run on the enrolled endpoint.
