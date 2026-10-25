# SentinelX — ActivePieces Workflows

## 1. Overview

ActivePieces is currently used for workflow orchestration in SentinelX. The workflows are maintained in the ActivePieces project, while this document records their purpose, configuration status, and testing progress.

**Important:** Documenting a workflow in GitHub does not export, copy, or execute that workflow.

## 2. Windows Failed-Login Ingestion

**Workflow:** SX Core v1 - Ingest Windows Failed Login

**Purpose:** Receive and validate supported Windows failed-login events and create a case for an accepted event.

### Configured Processing Steps

1. Receive an incoming webhook request.
2. Validate and normalize the event.
3. Check for a duplicate event.
4. Route invalid requests to an HTTP 400 response.
5. Route duplicate events to an HTTP 409 response.
6. Create a case record for an accepted event.
7. Return an HTTP 201 response for a successfully created case.

### Input and Authentication

- The workflow uses header authentication.
- The configured authentication header name is `X-SentinelX-Key`.
- The initial workflow is designed to accept the supported `windows_failed_login` event type and sample-test data.
- Authentication secrets must remain in the secure configuration and must never be committed to this repository.

### Verified Configuration Status

- Flow validation: valid at the last recorded inspection.
- Configured steps: 8 of 8 valid.
- Structural validation issues: 0 at that inspection.
- Published status: unpublished at the last recorded inspection.
- Enabled status: disabled at the last recorded inspection.
- Live HTTP authentication: not yet verified.

A successful configuration validation does not prove that live requests or authentication work correctly.

## 3. Repeated Authentication Failure Evaluation

**Workflow:** SX Core v1 - Evaluate Repeated Auth Failures

**Purpose:** Support detection of repeated authentication failures.

**Status:** Under development. Runtime effectiveness must be verified through actual workflow tests.

## 4. Security and Testing Requirements

Before conducting live webhook tests:

1. Verify the configured authentication secret securely without exposing it.
2. Review the endpoint exposure risk.
3. Obtain explicit authorization before publishing or enabling the workflow.
4. Test valid, invalid, missing-authentication, duplicate, and malformed requests.
5. Verify actual HTTP responses, workflow runs, and case records.
6. Disable the test endpoint when it is no longer required.

## 5. Data Protection

- Do not commit authentication secrets or API keys.
- Do not commit raw workflow exports before checking them for sensitive values.
- Do not upload private customer logs or case evidence.
- Record only verified test results.

## 6. Current Status

The ingestion workflow has been configured and structurally validated. Live authentication and end-to-end HTTP testing remain outstanding.

This document reflects the last recorded inspection. Recheck the workflow in ActivePieces before relying on its current status.
:::

### 3. File save karo

- **Commit changes** par click karo.
- Commit message likho: `Document ActivePieces workflow status`.
- Dobara **Commit changes** kar do.

---

## Iske baad hamara next major step

Ab hum baar-baar folders aur documentation nahi banayenge. Agla kaam SentinelX ka **actual GUI prototype** shuru karna hai—dark black background, red aur gold accents ke saath.

GUI banane se pehle mujhe bas yeh confirm karna hai: tumhari GitHub repository mein `README.md`, `docs/` aur baqi folders ban chuke hain na?