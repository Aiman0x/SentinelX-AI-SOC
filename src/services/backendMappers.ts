import type { Alert, Severity } from '../types/alert';
import type { SecurityCase, CaseStatus } from '../types/case';
import type { Asset, AssetType, Criticality } from '../types/asset';
import type { DetectionRule, AuditRecord, InvestigationRecord, EvidenceRecord } from '../types/extra';
import type { Integration } from '../types/integration';

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
  return s === 'critical' ? 'critical' : s === 'high' ? 'high' : s === 'medium' ? 'medium' : s === 'low' || s === 'informational' ? 'low' : 'unclassified';
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
  const ids = arr(c.event_ids ?? c.evidence_event_ids);
  const sourceIps = arr(c.source_ips);
  const findingId = str(c.finding_id, str(row.id, 'finding-unknown'));
  const statusText = str(c.status, str(c.detection_status, 'open')).toLowerCase();
  const status: Alert['status'] = statusText.includes('false') ? 'false_positive'
    : statusText.includes('resolved') ? 'resolved'
    : statusText.includes('investigat') || statusText.includes('confirm') ? 'investigating' : 'open';
  let mitreItems: unknown[] = [];
  if (Array.isArray(c.mitre_json)) mitreItems = c.mitre_json;
  else if (typeof c.mitre_json === 'string') { try { const parsed = JSON.parse(c.mitre_json); if (Array.isArray(parsed)) mitreItems = parsed; } catch { /* no MITRE mapping */ } }
  return {
    id: findingId, eventId: ids[0] ?? str(c.incident_key, findingId), ruleName: str(c.rule_name, str(c.title, 'Security detection incident')),
    severity: severity(c.severity), source: str(c.source_summary, 'SentinelX Detection Engine'), asset: str(c.host, 'Unknown asset'),
    sourceIp: sourceIps.join(', ') || str(c.source_ip, '—'), timestamp: date(c.detected_at ?? c.last_received_at ?? c.last_seen ?? c.updated_at ?? c.first_seen),
    status,
    summary: str(c.rationale, str(c.description, 'Detection candidate requires analyst review.')),
    rawEvent: { incident_key: str(c.incident_key), event_count: Number(c.event_count ?? 0), evidence_count: Number(c.evidence_count ?? 0), linked_event_ids: ids.join(','), confidence: Number(c.confidence ?? 0) },
    evidence: ids, relatedAlertIds: [], mitre: mitreItems.filter((x): x is Record<string, unknown> => !!x && typeof x === 'object').map(x => ({ id: str(x.id), name: str(x.name, 'MITRE technique'), tactic: str(x.tactic, 'Unknown') })).filter(x => !!x.id),
    nextSteps: ['Verify the source telemetry and timestamps.', 'Review related authentication and endpoint events.', 'Confirm asset criticality before response.'],
    caseId: str(c.case_id) || undefined,
  };
}

export function mapCase(row: Row): SecurityCase {
  const c = cells(row);
  const id = str(c['Case ID'], str(c.case_id, str(row.id, 'case-unknown')));
  const statusText = str(c.Status, str(c.status)).toLowerCase();
  const status: CaseStatus = statusText.includes('closed') ? 'closed' : statusText.includes('resolved') ? 'resolved' : statusText.includes('contain') ? 'contained' : statusText.includes('triag') || statusText.includes('investig') || statusText.includes('escalat') ? 'investigating' : 'open';
  const severityValue = severity(c.Severity ?? c.severity);
  const rawValue = c['Raw Evidence'] ?? c.raw_evidence ?? c.event_data;
  const raw = typeof rawValue === 'string' ? rawValue : rawValue ? JSON.stringify(rawValue) : '';
  const parseObject = (value: unknown): Record<string, unknown> => {
    if (value && typeof value === 'object' && !Array.isArray(value)) return value as Record<string, unknown>;
    if (typeof value === 'string') { try { const parsed = JSON.parse(value); return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {}; } catch { return {}; } }
    return {};
  };
  const analysis = parseObject(c['AI Analysis'] ?? c.ai_analysis);
  const investigationPlan = parseObject(c['Investigation Plan'] ?? c.investigation_plan);
  const sourceEventId = str(c['Source Event ID'], str(c.event_id));
  const sourceSchema = str(c['Source Schema'], str(c.source_schema, 'legacy_import'));
  const dataOrigin = str(c['Data Origin'], str(c.data_origin, 'UNKNOWN'));
  const sourceVerification = str(c['Source Verification'], str(c.source_verification,
    dataOrigin === 'REAL_UNVERIFIED' ? 'Source marked REAL_UNVERIFIED; authenticity has not been independently confirmed.' : 'Not recorded'));
  const eventType = str(c.event_type, str(c['Source Type'], str(c['Source'], 'security_event')));
  const host = str(c.host, str(c['Asset ID'], str(c['Source'])));
  const eventTime = str(c['Event Time'], str(c.event_time, str(c.received_at, str(c['Created At']))));
  const sourceIp = str(c.source_ip, 'not recorded');
  const username = str(c.username, 'not recorded');
  const verdict = str(analysis.verdict);
  const confidence = Number(analysis.confidence);
  const riskScore = Number(analysis.risk_score);
  const rowOverview = str(c.overview);
  const overview = verdict
    ? `${verdict} · Confidence ${Number.isFinite(confidence) ? confidence + '/100' : 'not recorded'} · Risk score ${Number.isFinite(riskScore) ? riskScore + '/100' : 'not recorded'}.`
    : str(investigationPlan.understanding, rowOverview || `Unverified ${eventType} record on ${host || 'unknown host'} at ${eventTime || 'unknown time'}. Source IP: ${sourceIp}. Account: ${username}. Data origin: ${dataOrigin}. No historical AI investigation report is attached.`);
  const timelineRaw = c['Evidence Timeline'] ?? c.evidence_timeline;
  let timelineItems: Record<string, unknown>[] = [];
  if (Array.isArray(timelineRaw)) timelineItems = timelineRaw.filter((x): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x));
  else if (typeof timelineRaw === 'string') { try { const parsed = JSON.parse(timelineRaw); if (Array.isArray(parsed)) timelineItems = parsed.filter((x): x is Record<string, unknown> => !!x && typeof x === 'object' && !Array.isArray(x)); } catch { /* use the event metadata fallback below */ } }
  const seenTimeline = new Set<string>();
  const timeline = timelineItems.map((item, index) => {
    const time = str(item.time, eventTime);
    const title = str(item.event, 'Investigation evidence');
    const detail = str(item.source, 'source not recorded');
    const key = [time, title, detail].join('|');
    if (seenTimeline.has(key)) return null;
    seenTimeline.add(key);
    return { id: id + '-timeline-' + index, time: date(time), title, detail, kind: 'evidence' as const };
  }).filter((item): item is NonNullable<typeof item> => item !== null);
  if (!timeline.length && eventTime) {
    timeline.push({
      id: id + '-source-event', time: date(eventTime),
      title: 'Original source event: ' + eventType,
      detail: `Host: ${host || 'not recorded'} · Account: ${username} · Source IP: ${sourceIp} · Origin: ${dataOrigin}`,
      kind: 'evidence'
    });
  }
  const recommended = arr(analysis.actions ?? c['Recommended Actions'] ?? c.recommended_actions);
  const evidenceIds = [...new Set(arr(c.evidence_event_ids))];
  return {
    id, title: str(c['Case Title'], str(c.case_title, eventType === 'security_event' ? 'Security investigation' : eventType)), severity: severityValue, status,
    assignee: str(c.Assignee, 'Unassigned'), assets: [str(c['Asset ID'], str(c.host, str(c['Source'])))].filter(Boolean),
    createdAt: date(c['Created At'] ?? c.created_at ?? c.event_time), updatedAt: date(c['Updated At'] ?? c.updated_at ?? c['Created At'] ?? c.event_time),
    overview, notes: [], evidence: evidenceIds, alertIds: arr(c.alert_ids),
    timeline, recommended,
    sourceSchema, dataOrigin, sourceVerification, sourceEventId, rawEvidence: raw, legacyRecord: sourceSchema !== 'security_incidents',
    analysis: Object.keys(analysis).length ? analysis : undefined,
    investigationPlan: Object.keys(investigationPlan).length ? investigationPlan : undefined,
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
  const ruleKey = str(c.ruleKey, str(c.rule_key, str(c['Rule ID'], str(row.id, 'rule-unknown'))));
  const name = str(c.title, str(c['Rule Name'], 'Detection rule'));
  const enabledValue = c.enabled;
  const isBuiltin = Boolean(c.ruleKey) && enabledValue === undefined && c.rule_type === undefined && c.ruleType === undefined;
  const enabled = enabledValue === true || enabledValue === 1 || enabledValue === '1' || isBuiltin;
  const mitreValue = c.mitre ?? c.mitre_json ?? c['MITRE Technique'];
  let mitre: string[] = [];
  if (Array.isArray(mitreValue)) mitre = mitreValue.map(item => typeof item === 'string' ? item : item && typeof item === 'object' ? str((item as Record<string, unknown>).id) : '').filter(Boolean);
  else if (typeof mitreValue === 'string') { try { const parsed = JSON.parse(mitreValue); if (Array.isArray(parsed)) mitre = parsed.map(item => typeof item === 'string' ? item : item && typeof item === 'object' ? str((item as Record<string, unknown>).id) : '').filter(Boolean); } catch { mitre = mitreValue.split(/[;,\s]+/).filter(Boolean); } }
  const severityValue = c.severity ?? c.Severity;
  const ruleType = str(c.ruleType, str(c.rule_type, isBuiltin ? 'builtin' : 'custom'));
  const prefix = ruleKey.split('-')[1] || '';
  const category = prefix === 'AUTH' ? 'Authentication' : prefix === 'END' ? 'Endpoint' : prefix === 'NET' ? 'Network' : prefix === 'WIN' ? 'Windows' : 'Custom';
  const sigma = str(c.sigmaYaml, str(c.sigma_yaml));
  const description = str(c.description, str(c.Description, 'Runtime detection rule.'));
  const logic = sigma || str(c.definition_json, description);
  const tested = c.lastTested ?? c.last_tested ?? c['Last Tested'];
  const maturity: DetectionRule['maturity'] = tested ? 'in_testing' : 'unvalidated';
  return {
    id: ruleKey, name, description, category, severity: severity(severityValue),
    source: ruleType === 'sigma' ? 'Custom Sigma rule' : isBuiltin ? 'SentinelX Worker detection engine' : 'Custom detection rule',
    mitre, status: enabled ? 'enabled' : 'disabled',
    lastTested: tested ? date(tested) : undefined,
    maturity,
    requiredEvidence: arr(c.requiredEvidence ?? c.required_evidence ?? c['Required Evidence']),
    logic,
    response: arr(c.response ?? c['Response Recommendations']),
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
  return rows.map((row) => {
    const item = obj(row);
    const health = obj(item.health);
    const fields = (Array.isArray(item.fields) ? item.fields : []).map((f) => {
      const v = obj(f);
      return { key: str(v.key), label: str(v.label, str(v.key)), placeholder: str(v.placeholder), secret: v.type === 'password', type: (v.type === 'password' || v.type === 'url' ? v.type : 'text') as 'password' | 'url' | 'text', required: v.required === true, help: str(v.help) || undefined };
    });
    const configured = item.configured === true;
    const verified = item.verified === true || health.ok === true;
    return {
      id: str(item.id), name: str(item.name), purpose: str(item.purpose, str(item.description)),
      category: str(item.category, 'Endpoint') as Integration['category'],
      state: verified ? 'connected' : configured ? 'disconnected' : 'not_configured',
      configured, verified, lastHealthCheck: typeof item.lastHealthCheck === 'string' ? date(item.lastHealthCheck) : undefined,
      configuredKeys: arr(item.configuredKeys), capabilities: arr(item.capabilities), fields,
      schema: obj(item.schema) as Integration['schema'],
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
  let payload: Record<string, unknown> = {};
  const rawPayload = c.payload_json ?? c['Payload JSON'];
  if (typeof rawPayload === 'string') { try { const parsed = JSON.parse(rawPayload); if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) payload = parsed as Record<string, unknown>; } catch { /* preserve metadata even if payload is malformed */ } }
  const excerptValue = payload.message ?? payload.excerpt ?? payload.rawEvent ?? payload.normalized ?? payload.event ?? rawPayload;
  const excerpt = typeof excerptValue === 'string' ? excerptValue : excerptValue ? JSON.stringify(excerptValue) : 'No evidence excerpt recorded.';
  const captured = c.captured_at ?? c['Collected At'];
  const evidenceType = str(c.evidence_type, str(c['Evidence Classification'], 'Detection evidence'));
  return {
    id: str(c.id, str(c['Evidence ID'], 'evidence-unknown')),
    caseId: str(c.incident_id, str(c['Case ID'], str(c.incident_title, '—'))),
    stepName: str(c.rule_key, str(c['Step Name'], 'Detection rule evidence')),
    sourceIntegration: str(payload.source, str(c['Source Integration'], 'SentinelX event pipeline')),
    toolName: str(c.evidence_type, str(c['Tool Name'], 'Security event evidence')),
    excerpt: excerpt.slice(0, 12000),
    collectedAt: date(captured),
    dataOrigin: str(payload.dataOrigin, str(payload.data_origin, str(c['Data Origin'], 'REAL_TELEMETRY'))),
    executionStatus: str(c['Execution Status'], 'Captured'),
    evidenceHash: str(c.sha256, str(c['Evidence Hash'], '—')),
    relevance: str(c.Relevance, 'Matched detection evidence'),
    classification: evidenceType,
  };
}
