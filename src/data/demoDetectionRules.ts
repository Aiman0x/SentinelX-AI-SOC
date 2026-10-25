import type { DetectionRule } from '../types/extra';
import { minutesAgo } from '../utils/formatDate';

/** DEMO DATA — descriptive rule definitions only. Nothing here is evaluated by the browser. */
export const demoRules: DetectionRule[] = [
  {
    id: 'SXR-001', name: 'Repeated Authentication Failures', category: 'Credential Access', severity: 'high',
    source: 'Windows Security', mitre: ['T1110'], status: 'enabled', lastTested: minutesAgo(1440), maturity: 'validated',
    description: 'Multiple failed logons for one account from one source in a short window.',
    requiredEvidence: ['Event ID 4625', 'Source IP', 'Target account'],
    logic: 'count(EventID=4625) by (TargetUserName, IpAddress) >= 10 within 10m',
    response: ['Check for later successful logon', 'Review lockout policy'],
  },
  {
    id: 'SXR-002', name: 'Failed Login Followed by Successful Login', category: 'Initial Access', severity: 'critical',
    source: 'Windows Security', mitre: ['T1078', 'T1110'], status: 'enabled', lastTested: minutesAgo(1440), maturity: 'in_testing',
    description: 'A successful logon from the same source shortly after many failures.',
    requiredEvidence: ['Event IDs 4625 and 4624', 'Same source IP', 'Time correlation'],
    logic: 'sequence by IpAddress: 4625 x >=10 then 4624 within 15m',
    response: ['Verify with the account owner', 'Consider approved password reset'],
  },
  {
    id: 'SXR-003', name: 'Suspicious Script Interpreter', category: 'Execution', severity: 'high',
    source: 'Sysmon', mitre: ['T1059.001', 'T1059.005'], status: 'enabled', lastTested: minutesAgo(4320), maturity: 'in_testing',
    description: 'Script interpreters launched with obfuscation flags or from unusual parents.',
    requiredEvidence: ['Sysmon EID 1', 'CommandLine', 'ParentImage'],
    logic: 'Image in (powershell.exe, wscript.exe) AND CommandLine matches (-enc|-w hidden|-nop)',
    response: ['Decode command in isolated environment', 'Collect process tree'],
  },
  {
    id: 'SXR-004', name: 'Unexpected Remote Logon', category: 'Lateral Movement', severity: 'high',
    source: 'Windows Security', mitre: ['T1021.001'], status: 'enabled', lastTested: minutesAgo(10000), maturity: 'unvalidated',
    description: 'Remote interactive logon from outside an allow-listed range.',
    requiredEvidence: ['Event ID 4624 LogonType 10', 'Source IP allow list'],
    logic: '4624 AND LogonType=10 AND IpAddress NOT IN admin_jump_hosts',
    response: ['Confirm planned change', 'Review session commands'],
  },
  {
    id: 'SXR-005', name: 'Persistence Change', category: 'Persistence', severity: 'high',
    source: 'Sysmon / Windows Security', mitre: ['T1547.001', 'T1136'], status: 'draft', lastTested: undefined, maturity: 'unvalidated',
    description: 'New autorun registry values, scheduled tasks or accounts.',
    requiredEvidence: ['Sysmon EID 13', 'Event ID 4720'],
    logic: 'EID 13 TargetObject contains "\\\\CurrentVersion\\\\Run" OR EventID=4720',
    response: ['Preserve evidence', 'Plan removal with approval'],
  },
  {
    id: 'SXR-006', name: 'Unusual Outbound Connection Pattern', category: 'Command and Control', severity: 'medium',
    source: 'Sysmon / Network', mitre: ['T1071.001'], status: 'disabled', lastTested: minutesAgo(20000), maturity: 'unvalidated',
    description: 'Beacon-like periodic connections to rarely seen destinations.',
    requiredEvidence: ['Sysmon EID 3', 'Destination reputation'],
    logic: 'stddev(interval) < 5s AND count >= 10 AND destination first_seen < 7d',
    response: ['Check reputation with approved source', 'Review proxy logs'],
  },
  {
    id: 'SXR-007', name: 'Critical Asset Without Monitoring', category: 'Coverage', severity: 'medium',
    source: 'SentinelX Inventory', mitre: [], status: 'enabled', lastTested: minutesAgo(600), maturity: 'validated',
    description: 'Critical assets registered with no verified telemetry.',
    requiredEvidence: ['Asset inventory', 'Last event time'],
    logic: 'asset.criticality = critical AND (lastEvent IS NULL OR lastEvent < now-24h)',
    response: ['Plan agent deployment', 'Verify telemetry arrives'],
  },
];
