# SentinelX Testing

## Purpose
This directory documents test procedures and verified results for SentinelX components.

## Testing Principles
- Use synthetic or authorized test data.
- Verify actual outputs rather than assuming a test passed.
- Record failures and unexpected behavior.
- Never include passwords, API keys, webhook secrets, or sensitive customer information in test artifacts.

## Planned Test Areas

### 1. Event Validation
Verify that valid events are accepted and malformed or unsupported events are rejected.

### 2. Duplicate Detection
Verify that an event already processed is not incorrectly created as a new case.

### 3. Authentication
Verify that requests with valid credentials are handled correctly and requests with invalid or missing credentials are rejected.

### 4. Case Creation
Verify that accepted events create the expected case record.

### 5. Detection Rules
Verify detection behavior using suitable synthetic events, including expected matches and non-matches.

### 6. Integration Health
Verify whether each configured defensive integration is reachable and operating as expected.

### 7. GUI
Test navigation, data display, error handling, and the accuracy of information shown to analysts.

## Test Results Template

For each test, record:
- Test ID
- Component
- Preconditions
- Test input
- Expected result
- Actual result
- Pass or fail
- Date tested
- Notes and limitations

## Current Status
Live webhook authentication testing remains unverified. Other tests should be marked complete only when their actual results have been reviewed.

## Security
Do not commit real credentials, private security logs, or sensitive incident evidence.
## Current frontend checks

- `npm run typecheck` / `npm run build` must pass (TypeScript strict mode).
- Automated UI tests are not written yet.
