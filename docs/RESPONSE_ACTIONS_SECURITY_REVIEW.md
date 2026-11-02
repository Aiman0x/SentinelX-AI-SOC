# Response Actions: Security Review and Production Gate

Status: approval-gated Cloudflare IP-block path implemented on the feature branch; NOT deployed or production-validated. Host isolation is not implemented.

## Current control flow
1. An analyst submits an exact IP, evidence/reason and optional tenant-local case ID to POST /api/approvals.
2. The Worker records the request with authenticated requester ID, audit entry and 15-minute expiry. It does not execute anything.
3. A different owner/admin reviews the request and records Approved/Rejected. Requester self-approval is denied.
4. Only the same authenticated approver can invoke POST /api/response/execute/:approvalId. The executor accepts only block_ip, requires an exact IP address, checks expiry, and atomically claims the approval to prevent duplicate execution.
5. The executor uses the approver's own encrypted cloudflare_response integration (API token + one zone ID), sends a Cloudflare zone IP Access Rule request, attempts read-back verification, and writes audit/execution results. Credentials are never returned to the browser or written to audit logs.
6. An ambiguous/failed execution is not automatically retried. Inspect Cloudflare and the audit record before any new approval is created.

## Connector setup
In Integrations → Cloudflare Response, configure a dedicated Cloudflare API token and exact Zone ID. Grant only permissions required to read the selected zone and create/read its IP Access Rules. Scope the token to the intended zone; do not use a global account key. Test the connection before requesting an action. The integration is action-only and excluded from the AI read-only tool catalog.

## Important limitations
- The real-action executor currently supports Cloudflare IP block only.
- Host isolation is not implemented; do not treat a Wazuh connection as permission to isolate hosts. A vendor-specific EDR adapter, exact asset identity, approval binding, verification and rollback workflow must be implemented separately.
- Cloudflare block rules can interrupt legitimate service. Use a test zone first and document rule removal/expiry before production.
- The executor is not deployed and has not passed live provider tests or an independent security review.

## Mandatory pre-production review
- Apply and verify migrations 0002_soc_data.sql through 0005_response_approval_hardening.sql in a non-production D1 database first.
- Run unit/integration tests for cross-tenant access, requester self-approval, unauthorized roles, expired approvals, changed targets, duplicate/concurrent execution, invalid IPs, token failure, provider timeout, and inconclusive read-back.
- Review approval immutability: no request fields may be changed after approval. Verify the action binding hash against the exact stored request before executing.
- Add an explicit rollback/removal operation with a separate approval and verified provider rule ID before production.
- Add rate limits and alerting for repeated execution failures and provider API errors.
- Test audit-log failure behavior. Execution must not start unless the start audit entry is durably recorded.
- Use staging zone and benign test IPs; verify actual rule state through provider API. Do not run disruptive tests against production customer IPs.
- Conduct an independent security review and authorized penetration test covering authentication/session handling, role bypass, IDOR, tenant isolation, CSRF/CORS, approval race conditions, secret handling, SSRF, replay, rate limits and audit tampering.
- Enable production actions only after written approval by the system owner and a documented incident-response/rollback runbook.

## Operational observability
Every action should have unique approval and execution attempt IDs, actor identities, timestamps, action type, normalized target, provider rule ID, provider result, verification state and audit references. Never log API tokens or unrelated event payloads. Alert on execution start without completion, failed verification, and audit write failures.