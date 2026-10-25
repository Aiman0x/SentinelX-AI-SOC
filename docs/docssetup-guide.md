# SentinelX — Setup Guide

## 1. Purpose

This guide documents the initial preparation required to work on SentinelX.

SentinelX is currently under development. The instructions below describe the development setup and security precautions; they do not imply that a complete standalone application is available.

## 2. Prerequisites

Before contributing to the project, prepare the following:

- A GitHub account and access to the SentinelX repository
- Access to the SentinelX ActivePieces project
- A modern web browser
- A development environment appropriate for the components being implemented
- Sample security events for authorized testing

Additional software requirements will be documented when specific integrations are implemented and verified.

## 3. ActivePieces Workflow

The initial event-ingestion workflow is maintained in ActivePieces.

Current workflow:

`SX Core v1 - Ingest Windows Failed Login`

The workflow is designed to validate supported Windows failed-login events, check for duplicates, create a case, and return an appropriate HTTP response.

Its current live authentication status must be verified before the workflow is considered operational.

## 4. Development and Testing

Use sample or synthetic security events during initial development.

Before testing a workflow:

1. Review its current configuration.
2. Verify that required fields and validation rules are correct.
3. Confirm that authentication is configured appropriately.
4. Check whether publishing will expose an endpoint to the internet.
5. Obtain the necessary authorization before publishing or sending live requests.
6. Verify actual responses and resulting records.
7. Disable temporary test endpoints when testing is complete, if they are no longer needed.

Record actual test results instead of assuming that a successful configuration check proves runtime behavior.

## 5. Credential Management

Never store authentication secrets directly in source files or documentation.

Do not commit:

- API keys
- Webhook authentication secrets
- Passwords
- Private tokens
- `.env` files containing real credentials
- Sensitive customer logs or investigation data

Use an appropriate secure credential store for secrets. Share only sanitized configuration examples.

## 6. GitHub Contribution Workflow

When making changes:

1. Review the existing files before editing.
2. Create a separate branch for substantial changes.
3. Make a small, focused change.
4. Review the changes for credentials and sensitive data.
5. Commit the change with a descriptive message.
6. Test the change before merging it into the main branch.

Do not upload backups, database exports, or unrelated local files.

## 7. Troubleshooting

### Workflow validation fails
Review the indicated step and its required fields before changing the workflow.

### Authentication fails
Verify the configured header name and the securely stored credential. Never paste the secret into a public issue or GitHub commit.

### Duplicate event is rejected
Check whether the event identifier was already processed.

### A case is not created
Review the workflow run and its routing conditions, then verify whether the case record exists.

### An integration is unavailable
Check its configuration, permissions, service status, and documented requirements.

## 8. Current Limitations

SentinelX is in development. The final GUI, standalone packaging, complete integrations, and investigation-assistance capabilities are not yet documented as fully operational.

Setup instructions will be expanded as the implementation becomes available and is verified.