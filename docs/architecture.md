# SentinelX — System Architecture

## 1. Overview

SentinelX is designed as a modular, AI-assisted defensive security platform. Its architecture separates event ingestion, detection, case management, investigation assistance, and defensive integrations.

The modular approach allows components to be developed, tested, and improved independently.

## 2. High-Level Architecture

```text
Security Event Sources
        |
        v
Event Ingestion
        |
        v
Validation and Normalization
        |
        v
Duplicate Event Check
        |
        v
Case Management
        |
        v
Detection and Alert Evaluation
        |
        v
Investigation and Evidence
        |
        v
Analyst Recommendations
        |
        v
Authorized Response Workflow
```

This diagram represents the intended workflow. Not all stages are implemented or connected yet.

## 3. Architecture Components

### 3.1 Event Sources

Potential sources include:

- Windows security events
- Linux system logs
- Server security events
- Network security alerts
- Supported defensive security tools

The initial workflow uses sample Windows failed-login events.

### 3.2 Event Ingestion

The ingestion component receives supported events through a configured webhook.

Its responsibilities include:

- Checking required fields
- Validating event formats
- Normalizing event information
- Rejecting unsupported event types
- Detecting duplicate event identifiers

### 3.3 Detection Engine

The detection component evaluates security events against defined detection rules.

Planned examples include:

- Repeated authentication failures
- Failed login followed by a successful login
- Suspicious script interpreter activity
- Unexpected remote logons
- Persistence-related changes

Detection rules must be tested against suitable sample data before being described as validated.

### 3.4 Case Management

The case management component organizes suspicious events into investigation records.

Potential case information includes:

- Event identifier
- Event timestamp
- Source system
- Source IP address, when available
- Severity
- Detection category
- Investigation status
- Evidence references
- Analyst notes

### 3.5 Investigation Assistance

A future investigation component will help explain:

- What happened
- Which systems or accounts may be involved
- What evidence supports the finding
- Why the activity may be suspicious
- Which additional checks are appropriate
- Which defensive actions an analyst should consider

Recommendations must distinguish confirmed evidence from assumptions.

### 3.6 Defensive Integrations

Potential integrations will be evaluated according to feasibility, hardware requirements, licensing, and compatibility.

Each integration must have documented setup instructions and a verified test procedure.

### 3.7 Response Workflow

Response actions may affect real systems. Consequently, potentially disruptive actions should require appropriate authorization and should be recorded for auditing.

## 4. Security Controls

The design should include:

- Authentication for event-ingestion endpoints
- Input validation
- Duplicate-event protection
- Secure handling of credentials
- Restricted access to investigation data
- Audit records for important actions
- Human approval for potentially disruptive response actions
- Safe handling of errors and failed integrations

## 5. Current Implementation Status

| Component | Status |
|---|---|
| ActivePieces event-ingestion workflow | Configured; live authentication untested |
| Input validation | Configured |
| Duplicate checking | Configured |
| Case creation | Configured |
| Detection evaluation | Under development |
| Defensive tool integrations | Planned and subject to testing |
| Investigation assistance | Planned |
| Graphical interface | Planned |
| Automated response | Requires further design and safeguards |

## 6. Future Development

Development will proceed incrementally, with each component tested before being treated as operational.

The architecture will be revised as implementation details and verified integrations become available.
## Frontend Architecture (Prototype)

`React + Vite + Tailwind` single-page app. UI components call a thin `services/` layer; services return demo data now and will call the SentinelX backend API when `VITE_API_BASE_URL` is set. Secrets and health checks must be handled server-side. Details: [gui-design.md](gui-design.md).
