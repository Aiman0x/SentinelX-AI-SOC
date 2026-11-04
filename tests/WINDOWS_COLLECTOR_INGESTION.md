# Windows Security Collector Ingestion Test

## Scope
Validates the tenant-scoped Cloudflare Worker endpoint for read-only Windows Security Event ID 4625 telemetry. This procedure uses synthetic data first. It does not require publishing an ActivePieces flow.

## Endpoint contract
- Method: `POST`
- Path: `/api/collector/events`
- Authentication: `Authorization: Bearer <collector-token>`
- JSON body:
```json
{
  "integrationId": "windows_security",
  "events": [{
    "eventId": "synthetic-4625-001",
    "observedAt": "2026-11-03T12:00:00.000Z",
    "payload": {
      "eventId": "win4625-TEST-WIN-12345",
      "eventType": "windows_failed_login",
      "host": "TEST-WIN",
      "username": "test-user",
      "sourceIp": "192.0.2.10",
      "source": "Windows Security Event Log",
      "dataOrigin": "LOCAL_WINDOWS",
      "eventData": { "EventID": 4625, "LogonType": 2 }
    }
  }]
}
```

## Expected behavior
1. A valid, active collector token receives HTTP 200 and a JSON response with `accepted: 1`, `integrationId: "windows_security"`, the matching collector ID, and `organizationScoped: true`.
2. The event is stored in `soc_records` under the collector's organization, entity type `telemetry_intake`, and source table `collector_events`.
3. The normalized row includes `Source Event ID`, `Event ID`, `Event Type`, `Event Time`, `Received At`, `Host`, `Username`, `Source IP`, `Source Integration`, `Data Origin`, `Validation Status`, and `Normalized Event JSON`.
4. The authenticated `GET /api/telemetry` route returns the row only to a user/service in the same organization.
5. Missing, invalid, or revoked tokens receive HTTP 401 and do not create a record.
6. Unsupported integration IDs, malformed bodies, empty batches, and batches over 100 events are rejected.
7. Re-sending the same event ID from the same collector updates the existing row rather than creating a duplicate.
8. A paused collector's config response includes `paused: true`; event and heartbeat writes are rejected with HTTP 423 until an owner/admin resumes it.
9. The GUI can pause/resume an enrolled collector; revocation remains a separate irreversible token action.

## Safety checks
- Never put a collector token in a URL, query string, source code, test fixture, or log.
- Create the collector through the authenticated GUI/API; only the token hash is stored in D1.
- Do not test with real personal account names or private IP/device details.
- Do not start the Windows collector until a token has been issued and stored locally.
- A successful HTTP response is not proof that the frontend displays the event; verify both D1 scoping and the Windows Telemetry page.
- Mark the test PASS only after the actual response and stored row have been inspected.

## Current status
Production Worker deployment is complete. Synthetic production smoke tests passed for Windows Event ID 4625 ingestion, normalized `GET /api/telemetry` visibility, collector config/heartbeat, dual-credential ActivePieces reads, revoked-token rejection, and tenant isolation. Temporary smoke-test collectors, records, and the temporary test organization were removed afterward.

The actual PowerShell/Python agents have not yet been run on the user's Windows host. GUI pause/resume was added and is awaiting its final deployed runtime smoke test.
