import type { Alert, Severity } from '../types/alert';
import type { SecurityCase, CaseStatus } from '../types/case';
import type { Asset, AssetType, Criticality } from '../types/asset';
import type { DetectionRule, AuditRecord, InvestigationRecord, EvidenceRecord } from '../types/extra';
import type { Integration } from '../types/integration';
import { demoIntegrations } from '../data/demoIntegrations';

type Row = { id?: string; cells?: Record<string, unknown> } & Record<string, unknown>;
const obj = (v: unknown): Record<string, unknown> => v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {};
const str = (v: unknown, fallback = ''): string => v == null || v === '' ? fallback : String(v);
const arr = (v: unknown): string[] => {
  if (Array.isArray(v)) return v.map(String);
  if (typeof v !== 'string' || !v) return [];
  try { const p = JSON.parse(v); return Array.isArray(p) ? p.map(String) : v.split(',').map(x => x.trim()).filter(Boolean); }
  catch { return v.split(',').map(x => x.trim()).filter(Boolean); }
};
const severity = (v: unknown): Severity => {
  const s = str(v).toLowerCase();
  return s === 'critical' ? 'critical' : s === 'high' ? 'high' : s === 'low' || s === 'informational' ? 'low' : 'medium';
};
const date = (v: unknown): string => {
  const d = v ? new Date(String(v)) : new Date(0);
  return Number.isNaN(+d) ? new Date(0).toISOString() : d.toISOString();
};
export function rowsFrom(payload: unknown): Row[] {
  if (Array.isArray(payload)) return payload as Row[];
  const p = obj(payload);
  if (Array.isArray(p.records)) return p.records as Row[];
  if (Array.isArray(p.data)) return p.data as Row[];
  if (p.data && typeof p.data === 'object') return rowsFrom(p.data);
  return [];
}
const cells = (row: Row) => ({ ...obj(row), ...obj(row.cells) });

export function mapFinding(row: Row): Alert {
  const c = cells(row);
  const ids = arr(c.evidence_event_ids);
  const sourceIps = arr(c.source_ips);
  const findingId = str(c.finding_id, str(row.id, 'finding-unknown'));
  return {
    id: findingId, eventId: ids[0] ?? findingId, ruleName: str(c.rule_name, 'Detection finding'),
    severity: severity(c.severity), source: 'SentinelX Detection Engine', asset: str(c.host, 'Unknown asset'),
    sourceIp: sourceIps.join(', ') || '—', timestamp: date(c.detected_at),
    status: str(c.detection_status).toLowerCase().includes('false') ? 'false_positive' : str(c.detection_status).toLowerCase().includes('confirmed') ? 'investigating' : 'open',
    summary: str(c.rationale, 'Detection candidate requires analyst review.'),
    rawEvent: { finding_id: findingId, rule_id: str(c.rule_id), event_count: Number(c.event_count ?? 0), threshold: Number(c.threshold ?? 0), window_minutes: Number(c.window_minutes ?? 0), data_origin: str(c.data_origin), test_status: str(c.test_status) },
    evidence: ids, relatedAlertIds: [], mitre: [], nextSteps: ['Verify the source telemetry and timestamps.', 'Review related authentication and endpoint events.', 'Confirm asset criticality before response.'],
    caseId: str(c.case_id) || undefined,
  };
}

export function mapCase(row: Row): SecurityCase {
  const c = cells(row);
  const id = str(c['Case ID'], str(c.case_id, str(row.id, 'case-unknown')));
  const statusText = str(c.Status, str(c.status)).toLowerCase();
  const status: CaseStatus = statusText.includes('closed') ? 'closed' : statusText.includes('resolved') ? 'resolved' : statusText.includes('contain') ? 'contained' : statusText.includes('triag') || statusText.includes('investig') || statusText.includes('escalat') ? 'investigating' : 'open';
  const severityValue = severity(c.Severity ?? c.severity);
  const raw = str(c['Raw Evidence'], str(c.raw_evidence));
  const timelineRaw = str(c['Evidence Timeline'], str(c.evidence_timeline));
  const recommended = arr(c['Recommended Actions'] ?? c.recommended_actions);
  return {
    id, title: str(c['Case Title'], str(c.case_title, 'Security investigation')), severity: severityValue, status,
    assignee: str(c.Assignee, 'Unassigned'), assets: [str(c['Asset ID'])].filter(Boolean),
    createdAt: date(c['Created At'] ?? c.created_at), updatedAt: date(c['Updated At'] ?? c.updated_at ?? c['Created At']),
    overview: str(c['AI Analysis'], str(c['Final Report'], raw || 'No investigation summary recorded.')),
    notes: [], evidence: arr(c.evidence_event_ids), alertIds: [str(c['Source Event ID'], str(c.event_id))].filter(Boolean),
    timeline: timelineRaw ? [{ id: id + '-timeline', time: date(c['Event Time'] ?? c['Created At']), title: 'Investigation evidence', detail: timelineRaw.slice(0, 500), kind: 'evidence' }] : [],
    recommended: recommended.length ? recommended : arr(c['Recommended Actions']),
  };
}

export function mapAsset(row: Row): Asset {
  const c = cells(row);
  const monitoringText = str(c['Monitoring Status']).toLowerCase();
  const monitoring: Asset['monitoring'] = monitoringText.includes('connect') && !monitoringText.includes('not') ? 'verified' : monitoringText.includes('degrad') || monitoringText.includes('stale') ? 'stale' : monitoringText.includes('not connected') || monitoringText.includes('unmonitored') || monitoringText.includes('retired') ? 'unmonitored' : 'registered';
  const typeText = str(c['Asset Type'], 'Server');
  const type: AssetType = /workstation|endpoint/i.test(typeText) ? 'Workstation' : /domain/i.test(typeText) ? 'Domain' : /network/i.test(typeText) ? 'Network device' : /cloud/i.test(typeText) ? 'Cloud service' : /database/i.test(typeText) ? 'Database' : 'Server';
  const critText = str(c.Criticality, 'medium').toLowerCase();
  const criticality: Criticality = critText === 'critical' || critText === 'high' || critText === 'low' ? critText : 'medium';
  const host = str(c['Hostname / Domain / IP'], '—');
  return { id: str(c['Asset ID'], str(row.id, 'asset-unknown')), name: str(c['Asset Name'], host), host, ip: '—', os: str(c['Operating System'], '—'), type, criticality, monitoring, method: str(c['Telemetry Source'], 'None'), lastVerified: c['Last Verified'] ? date(c['Last Verified']) : undefined };
}

export function mapRule(row: Row): DetectionRule {
  const c = cells(row);
  const statusText = str(c.Status).toLowerCase();
  const maturityText = str(c['Rule Maturity']).toLowerCase();
  return {
    id: str(c['Rule ID'], str(row.id, 'rule-unknown')), name: str(c['Rule Name'], 'Detection rule'),
    description: str(c.Description), category: str(c.Category, 'Other'), severity: severity(c.Severity),
    source: str(c['Required Data Source'], 'Not specified'), mitre: arr(c['MITRE Technique']),
    status: statusText.includes('enabled') ? 'enabled' : statusText.includes('disabled') ? 'disabled' : 'draft',
    lastTested: c['Last Tested'] ? date(c['Last Tested']) : undefined,
    maturity: maturityText.includes('operating on real') || maturityText.includes('validated') ? 'validated' : maturityText.includes('test') ? 'in_testing' : 'unvalidated',
    requiredEvidence: arr(c['Required Evidence']), logic: str(c['Detection Logic']), response: [],
  };
}

export function mapAudit(row: Row): AuditRecord {
  const c = cells(row);
  const outcome = str(c.Outcome).toLowerCase();
  const event = str(c['Event Type'], 'Audit event');
  const eventLower = event.toLowerCase();
  const actionType: AuditRecord['actionType'] = eventLower.includes('config') ? 'config' : eventLower.includes('approval') ? 'response' : eventLower.includes('create') || eventLower.includes('received') ? 'create' : eventLower.includes('update') ? 'update' : 'view';
  return {
    id: str(c['Audit ID'], str(row.id, 'audit-unknown')), time: date(c.Timestamp), actor: str(c.Actor, 'System'),
    actorType: str(c['Actor Type']).toLowerCase().includes('human') ? 'user' : 'service', action: event,
    actionType, target: str(c['Case ID'], str(c['Evidence Reference'], '—')),
    result: outcome.includes('fail') ? 'failure' : outcome.includes('block') || outcome.includes('denied') ? 'denied' : 'success',
    source: 'SentinelX Audit Log',
  };
}

export function mapIntegrationRows(payload: unknown): Integration[] {
  const rows = rowsFrom(payload);
  const configs = obj(obj(payload).configs);
  return demoIntegrations.map(base => {
    const match = rows.find(row => {
      const c = cells(row);
      const id = str(c['Integration ID']).toLowerCase();
      const name = str(c['Integration Name']).toLowerCase();
      return id.includes(base.id) || name.includes(base.name.toLowerCase());
    });
    const c = match ? cells(match) : {};
    const s = str(c['Connection Status']).toLowerCase();
    const state: Integration['state'] = s === 'connected' ? 'connected' : s.includes('degrad') ? 'error' : s.includes('fail') ? 'error' : s.includes('simulated') ? 'demo' : s.includes('not configured') ? 'not_configured' : s.includes('config') ? 'disconnected' : 'not_configured';
    const config = obj(configs[base.id]);
    const savedValues = obj(config.values) as Record<string, string>;
    const health = obj(config.health);
    const healthVerified = health.ok === true;
    // A successful /api/integrations request has already completed a real Activepieces webhook round-trip.
    const activepiecesReachable = base.id === 'activepieces';
    const configured = activepiecesReachable || config.configured === true || (!s.includes('not configured') && !!match);
    return {
      ...base, state: activepiecesReachable ? 'connected' : configured && state === 'not_configured' ? 'disconnected' : state,
      configured, verified: activepiecesReachable || healthVerified || s === 'connected',
      lastHealthCheck: activepiecesReachable ? new Date().toISOString() : (typeof health.checkedAt === 'string' ? date(health.checkedAt) : c['Last Health Check'] ? date(c['Last Health Check']) : undefined),
      savedConfig: savedValues, configuredKeys: arr(config.keys),
    };
  });
}


export function mapInvestigation(row: Row): InvestigationRecord {
  const c = cells(row);
  return {
    id: str(c['Correlation ID'], str(row.id, 'investigation-unknown')),
    caseId: str(c['Case ID'], '—'),
    createdAt: date(c['Created At']),
    eventCount: Number(c['Event Count'] ?? 0),
    findingCount: Number(c['Finding Count'] ?? 0),
    confidence: Number(c.Confidence ?? 0),
    dataOrigin: str(c['Data Origin'], 'UNKNOWN'),
    status: str(c['Investigation Status'], 'Needs Analyst Review'),
    narrative: str(c['Investigation Narrative'], 'No investigation narrative recorded.'),
    hosts: arr(c['Host Summary']),
    accounts: arr(c['Account Summary']),
    sourceIps: arr(c['Source IP Summary']),
    eventIds: arr(c['Related Event IDs']),
    signals: arr(c['Correlation Signals']),
  };
}


export function mapEvidence(row: Row): EvidenceRecord {
  const c = cells(row);
  return {
    id: str(c['Evidence ID'], str(row.id, 'evidence-unknown')),
    caseId: str(c['Case ID'], '—'),
    stepName: str(c['Step Name'], '—'),
    sourceIntegration: str(c['Source Integration'], '—'),
    toolName: str(c['Tool Name'], '—'),
    excerpt: str(c['Evidence Excerpt'], 'No evidence excerpt recorded.'),
    collectedAt: date(c['Collected At']),
    dataOrigin: str(c['Data Origin'], 'UNKNOWN'),
    executionStatus: str(c['Execution Status'], 'Unknown'),
    evidenceHash: str(c['Evidence Hash'], '—'),
    relevance: str(c.Relevance, 'Unrated'),
    classification: str(c['Evidence Classification'], 'Unclassified'),
  };
}
