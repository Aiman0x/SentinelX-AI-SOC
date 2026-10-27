# SentinelX GUI ↔ Backend API Contract

This contract is the handoff between the existing React GUI and the FastAPI bridge under `backend/`. The API bridge is scaffolded, but endpoints backed by ActivePieces data remain pending until their read-only webhook flows are configured and published.

## API endpoints

| Endpoint | Purpose | Current state |
|---|---|---|
| `GET /health` | API process health | Implemented |
| `GET /api/status` | Per-feature connection/readiness status | Implemented |
| `GET /api/capabilities` | Implemented and pending feature list | Implemented |
| `GET /api/alerts?limit=100` | Alert/finding data | Pending read webhook |
| `GET /api/cases?limit=100` | Cases | Pending read webhook |
| `GET /api/assets?limit=100` | Asset inventory | Pending read webhook |
| `GET /api/rules?limit=100` | Detection rules | Pending read webhook |
| `GET /api/integrations?limit=100` | Integration registry/status | Pending read webhook |
| `GET /api/audit?limit=100` | Audit trail | Pending read webhook |
| `GET /api/investigations?limit=100` | Correlation/investigation records | Pending read webhook |
| `GET /api/evidence?limit=100` | Evidence references | Pending read webhook |
| `POST /api/telemetry` | Forward a validated event to the existing ActivePieces telemetry receiver | Pending URL/secret configuration |

Read endpoints return a JSON array. A bridge may return `{"data":[...]}`, `{"items":[...]}`, or `{"records":[...]}`; FastAPI normalizes those forms to an array. A not-yet-configured feature returns HTTP 503 with a `FEATURE_PENDING` error. The frontend must not silently substitute demo records after that error.

## ActivePieces table mapping

Use existing tables, not duplicate tables:
- Alerts/detection findings: `SX Detection Findings v1` (confirm the GUI's alert type mapping before claiming it is fully compatible).
- Cases: `SX Cases v1` or `SentinelX Cases` (inspect which table is authoritative; do not combine duplicates without mapping).
- Assets: `SentinelX Asset Inventory`.
- Detection rules: `SentinelX Detection Rules`.
- Integrations: `SentinelX Security Integrations`.
- Audit: `SentinelX Audit Logs`.
- Investigations: `SX Correlation Investigations v1`.
- Evidence: `SentinelX Evidence References`.
- Incoming telemetry: `SX Telemetry Intake v1` and/or `SentinelX Incoming Events` as determined by the active receiver flow.

The GUI's TypeScript interfaces and these table schemas do not necessarily match. Add explicit mapping/normalization after inspecting sample rows; never claim a direct schema match based on names alone.

## Read-only webhook pattern

For each resource, create a dedicated ActivePieces Catch Webhook flow:
1. Require header authentication using a strong shared secret.
2. Use Tables → Find Records on the corresponding existing table, with a safe record limit.
3. Map table cells to a stable JSON response shape.
4. Return JSON in a synchronous webhook response.
5. Keep the flow read-only; do not update/delete rows from GET endpoints.
6. Publish and verify the flow before setting its URL in the backend environment.

Store webhook URLs and shared secrets only in the backend environment. Do not store them in the React app, GitHub source, or `VITE_*` variables.

## Current limitations

- The backend bridge is source code in the repository, not a deployed API server.
- GitHub Pages cannot host FastAPI. A separate HTTPS backend host is required for the public GUI.
- User/session authentication has not been implemented; do not expose the API publicly with real security data until authentication, authorization and tenant isolation are added.
- Case mutations, notes, status changes, rule changes, playbook execution and integration tests remain pending.
- Existing ActivePieces telemetry receiver is enabled, but its real webhook URL and secret must be configured privately on the backend host before the telemetry proxy can work.


## ActivePieces read bridge flows created

The following dedicated read-only flows were created in the existing ActivePieces project, placed in the `SentinelX GUI API Bridge` folder, and published/enabled. Their flow structure validation passed. They have **not** been called end-to-end yet.

| Resource | Flow ID | Existing table |
|---|---|---|
| Findings / alerts | `UhsSqbikoPuehW6jNxxCB` | `SX Detection Findings v1` |
| Cases / incidents | `N6GjE4o09li8aYi5Y5HXa` | `SentinelX Cases` |
| Assets | `TdJBojFRNAi6vLZ37OEzI` | `SentinelX Asset Inventory` |
| Detection rules | `VwL24wox3eS5HsmyFRQU4` | `SentinelX Detection Rules` |
| Integrations | `9NnORdUWUwdWPlV8cm3C9` | `SentinelX Security Integrations` |
| Audit | `p6DWQhGI5tmql8x78oIxL` | `SentinelX Audit Logs` |
| Investigations | `JgR36M68bNJYty2ec7RFV` | `SX Correlation Investigations v1` |
| Evidence | `HIBX4e0YsgCdXdQEIxINk` | `SentinelX Evidence References` |

Each flow requires the shared header `X-SentinelX-Bridge-Key` and returns a `data` array from the Tables Find Records step. Before deployment, copy each flow's actual webhook URL from the ActivePieces trigger panel and place it in the matching backend environment variable. Do not guess webhook URLs from flow IDs.

A shared bridge secret has been set on these new read flows. It is not stored in this repository. Configure the same value in the backend secret store/environment; rotate it before production deployment. The existing telemetry receiver uses its own separate header secret and must not reuse the bridge secret.
