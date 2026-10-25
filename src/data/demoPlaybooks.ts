import type { Playbook } from '../types/extra';

/**
 * DEMO DATA — playbook designs. "designed" = on paper only, "configured" = built in ActivePieces
 * but not yet proven, "executed" = a real run completed successfully (none in this prototype).
 */
export const demoPlaybooks: Playbook[] = [
  {
    id: 'PB-001', name: 'Repeated Login Failure Investigation',
    purpose: 'Validate, de-duplicate and open a case for repeated failed-logon events.',
    triggers: ['Webhook: Windows Event ID 4625 payload', 'Rule SXR-001 fires'],
    requiredEvidence: ['Source IP', 'Target account', 'Failure count & window'],
    plannedActions: ['Validate payload', 'Check duplicate', 'Create case', 'Notify analyst'],
    approval: 'None for read-only steps. Account lock/reset requires analyst approval.',
    lifecycle: 'configured',
    steps: [
      { id: 's1', label: 'Receive webhook', type: 'trigger', detail: 'ActivePieces webhook receives the normalised event.' },
      { id: 's2', label: 'Validate & normalise', type: 'decision', detail: 'Reject malformed payloads.', branches: [{ label: 'Valid', to: 's3' }, { label: 'Invalid → HTTP 400', to: 'end' }] },
      { id: 's3', label: 'Duplicate check', type: 'decision', detail: 'Look up the event hash.', branches: [{ label: 'New', to: 's4' }, { label: 'Duplicate → ignore', to: 'end' }] },
      { id: 's4', label: 'Create case', type: 'action', detail: 'Create a case record with evidence.' },
      { id: 's5', label: 'Notify analyst', type: 'notify', detail: 'Send a notification to the assigned analyst.' },
    ],
  },
  {
    id: 'PB-002', name: 'Suspicious Script Execution',
    purpose: 'Collect context around encoded or hidden script execution.',
    triggers: ['Rule SXR-003 fires'],
    requiredEvidence: ['Command line', 'Parent process', 'User'],
    plannedActions: ['Collect process tree', 'Decode command (isolated)', 'Enrich destination', 'Recommend containment'],
    approval: 'Analyst approval required before any host action.',
    lifecycle: 'designed',
    steps: [
      { id: 's1', label: 'Trigger from alert', type: 'trigger', detail: 'Alert SXR-003 arrives.' },
      { id: 's2', label: 'Collect process tree', type: 'enrich', detail: 'Read-only query through the EDR/Wazuh API.' },
      { id: 's3', label: 'Suspicious?', type: 'decision', detail: 'Analyst decision.', branches: [{ label: 'Yes', to: 's4' }, { label: 'No → close', to: 'end' }] },
      { id: 's4', label: 'Isolate endpoint', type: 'action', disruptive: true, detail: 'Network-isolate the host. Requires explicit approval.' },
    ],
  },
  {
    id: 'PB-003', name: 'Malware Alert Investigation',
    purpose: 'Triage endpoint AV detections and find the delivery vector.',
    triggers: ['Endpoint AV detection', 'ClamAV/YARA match'],
    requiredEvidence: ['File path & hash', 'User', 'Quarantine result'],
    plannedActions: ['Hash lookup (approved source)', 'Search other hosts', 'Check email gateway'],
    approval: 'Deleting files or blocking senders requires approval.',
    lifecycle: 'designed',
    steps: [
      { id: 's1', label: 'AV alert received', type: 'trigger', detail: 'Alert from the endpoint AV.' },
      { id: 's2', label: 'Hash enrichment', type: 'enrich', detail: 'Lookup with an approved intel source.' },
      { id: 's3', label: 'Search fleet for hash', type: 'enrich', detail: 'Read-only search.' },
      { id: 's4', label: 'Delete files', type: 'action', disruptive: true, detail: 'Remove remaining copies. Requires approval.' },
    ],
  },
  {
    id: 'PB-004', name: 'Critical Asset Alert',
    purpose: 'Fast-path escalation for alerts on critical assets.',
    triggers: ['Any alert ≥ high on an asset with criticality = critical'],
    requiredEvidence: ['Asset ID', 'Alert evidence'],
    plannedActions: ['Raise priority', 'Page on-call', 'Open case'],
    approval: 'Paging is automatic; containment requires approval.',
    lifecycle: 'designed',
    steps: [
      { id: 's1', label: 'Alert on critical asset', type: 'trigger', detail: 'Matches asset criticality.' },
      { id: 's2', label: 'Raise priority', type: 'action', detail: 'Set case severity to critical.' },
      { id: 's3', label: 'Page on-call', type: 'notify', detail: 'Notify the on-call analyst.' },
    ],
  },
  {
    id: 'PB-005', name: 'Incident Evidence Collection',
    purpose: 'Gather and preserve evidence for a case before any remediation.',
    triggers: ['Analyst clicks "Collect evidence" on a case'],
    requiredEvidence: ['Case ID', 'Asset list'],
    plannedActions: ['Export related alerts', 'Snapshot logs', 'Hash and store evidence'],
    approval: 'Read-only. Storage location must be access-controlled.',
    lifecycle: 'designed',
    steps: [
      { id: 's1', label: 'Manual trigger', type: 'trigger', detail: 'Analyst request.' },
      { id: 's2', label: 'Export alerts', type: 'enrich', detail: 'Pull related alerts for the case.' },
      { id: 's3', label: 'Hash & store', type: 'action', detail: 'Write evidence bundle with integrity hashes.' },
    ],
  },
  {
    id: 'PB-006', name: 'Response Approval',
    purpose: 'Gate disruptive actions behind explicit, logged approval.',
    triggers: ['Any playbook requests a disruptive action'],
    requiredEvidence: ['Requested action', 'Target', 'Justification', 'Requester'],
    plannedActions: ['Request approval', 'Record decision', 'Release or cancel action'],
    approval: 'Two-person approval for critical assets (planned).',
    lifecycle: 'designed',
    steps: [
      { id: 's1', label: 'Action requested', type: 'trigger', detail: 'A playbook asks for a disruptive action.' },
      { id: 's2', label: 'Approver decision', type: 'approval', detail: 'Approver reviews evidence.', branches: [{ label: 'Approved', to: 's3' }, { label: 'Denied → cancel', to: 'end' }] },
      { id: 's3', label: 'Execute action', type: 'action', disruptive: true, detail: 'Block IP / disable account / isolate host — through authorised integration only.' },
    ],
  },
];
