import type { Alert } from '../types/alert';
import type { CaseNote, CaseStatus, SecurityCase } from '../types/case';
import { apiGet, delay, isBackendConfigured } from './apiClient';
import { rowsFrom, mapCase } from './backendMappers';
import { createLocalStore } from './localStore';
import { updateAlert } from './alertsService';

export const casesStore = createLocalStore<SecurityCase[]>('sentinelx.live.cases.v1', () => []);
const nowIso = () => new Date().toISOString();
const uid = (p: string) => `${p}-${Math.random().toString(36).slice(2, 8)}`;

function mapSecurityIncident(row: Record<string, unknown>): SecurityCase {
  const severityText = String(row.severity ?? 'medium').toLowerCase();
  const severity: SecurityCase['severity'] = severityText === 'critical' ? 'critical'
    : severityText === 'high' ? 'high' : severityText === 'low' ? 'low' : 'medium';
  const statusText = String(row.status ?? 'open').toLowerCase();
  const status: CaseStatus = statusText === 'resolved' ? 'resolved'
    : statusText === 'investigating' ? 'investigating'
    : statusText === 'false_positive' ? 'closed' : 'open';
  const evidenceCount = Number(row.evidence_count ?? 0);
  const eventCount = Number(row.event_count ?? 0);
  const host = typeof row.host === 'string' ? row.host : '';
  const sourceIp = typeof row.source_ip === 'string' ? row.source_ip : '';
  const ruleKey = typeof row.incident_key === 'string' ? row.incident_key.split('|')[1] || row.incident_key : 'detection';
  const firstSeen = String(row.first_seen ?? nowIso());
  const lastSeen = String(row.last_seen ?? firstSeen);
  return {
    id: String(row.id ?? 'incident-unknown'),
    title: String(row.title ?? 'Security detection incident'),
    severity, status, assignee: 'Unassigned',
    assets: host ? [host] : [],
    createdAt: firstSeen, updatedAt: lastSeen,
    overview: String(row.description ?? 'A detection rule matched incoming security telemetry.')
      + ` Confidence: ${Number(row.confidence ?? 0)}%. Events: ${eventCount}. Source IP: ${sourceIp || 'not recorded'}.`,
    notes: [],
    evidence: evidenceCount ? [`${evidenceCount} evidence snapshot(s) stored with SHA-256 integrity hashes.`] : [],
    alertIds: [],
    timeline: [{
      id: String(row.id ?? 'incident') + '-detection',
      time: firstSeen,
      title: 'Detection rule matched',
      detail: `${ruleKey} · ${eventCount} linked event(s) · last seen ${lastSeen}`,
      kind: 'detection',
    }],
    recommended: [
      'Confirm whether the activity was authorized with the host or account owner.',
      'Review surrounding authentication, endpoint and network events for this host and account.',
      'Validate the source records before considering any containment action.',
    ],
    detectionIncident: true,
  };
}

/** Count unique unresolved detection incidents in the active 24-hour window only.
 * Legacy/manual case records are intentionally excluded from this dashboard metric. */
export async function loadActiveOpenIncidentCount(): Promise<number> {
  if (!isBackendConfigured) return 0;
  const payload = await apiGet<unknown>('/api/incidents?status=active&limit=200');
  const unresolved = rowsFrom(payload).filter((row) => {
    const status = String(row.status ?? 'open').toLowerCase();
    return !['resolved', 'closed', 'false_positive', 'false positive'].includes(status);
  });
  return new Set(unresolved.map((row) => String(row.id ?? '')).filter(Boolean)).size;
}

export async function loadCases(): Promise<SecurityCase[]> {
  if (isBackendConfigured) {
    const [incidentPayload, legacyPayload] = await Promise.all([
      apiGet<unknown>('/api/incidents?limit=100'),
      apiGet<unknown>('/api/cases'),
    ]);
    const incidents = rowsFrom(incidentPayload).map((row) => mapSecurityIncident(row));
    const legacyCases = rowsFrom(legacyPayload).map(mapCase);
    return [...incidents, ...legacyCases];
  }
  await delay(200);
  return casesStore.getSnapshot();
}
function nextCaseId(): string {
  const nums = casesStore.getSnapshot().map((c) => Number(c.id.split('-').pop()) || 0);
  return `SX-CASE-${String(Math.max(0, ...nums) + 1).padStart(4, '0')}`;
}
function patchCase(id: string, fn: (c: SecurityCase) => SecurityCase) {
  casesStore.set(casesStore.getSnapshot().map((c) => (c.id === id ? { ...fn(c), updatedAt: nowIso() } : c)));
}
export function createCase(input: { title: string; severity: SecurityCase['severity']; assignee: string; assets: string[]; overview: string; alertIds?: string[] }): SecurityCase {
  const c: SecurityCase = { id: nextCaseId(), title: input.title, severity: input.severity, status: 'open', assignee: input.assignee || 'Unassigned', assets: input.assets, createdAt: nowIso(), updatedAt: nowIso(), overview: input.overview, notes: [], evidence: [], alertIds: input.alertIds ?? [], timeline: [{ id: uid('t'), time: nowIso(), title: 'Case created (demo)', detail: 'Created in the SentinelX prototype.', kind: 'status' }], recommended: ['Assign an owner.', 'Collect and preserve evidence.'] };
  casesStore.set([c, ...casesStore.getSnapshot()]);
  return c;
}
export function createCaseFromAlert(alert: Alert, analyst: string): SecurityCase {
  const existing = alert.caseId ? casesStore.getSnapshot().find((c) => c.id === alert.caseId) : undefined;
  if (existing) return existing;
  const c = createCase({ title: `${alert.ruleName} on ${alert.asset}`, severity: alert.severity, assignee: analyst, assets: [alert.asset], overview: alert.summary, alertIds: [alert.id, ...alert.relatedAlertIds] });
  patchCase(c.id, (x) => ({ ...x, evidence: alert.evidence, recommended: alert.nextSteps, timeline: [{ id: uid('t'), time: alert.timestamp, title: alert.ruleName, detail: alert.summary, kind: 'detection' }, ...x.timeline] }));
  updateAlert(alert.id, { caseId: c.id, status: alert.status === 'open' ? 'investigating' : alert.status });
  return c;
}
export function addNote(caseId: string, author: string, text: string) {
  const note: CaseNote = { id: uid('n'), author, time: nowIso(), text };
  patchCase(caseId, (c) => ({ ...c, notes: [note, ...c.notes], timeline: [...c.timeline, { id: uid('t'), time: nowIso(), title: 'Analyst note', detail: text.slice(0, 120), kind: 'analyst' }] }));
}
export function setCaseStatus(caseId: string, status: CaseStatus, author: string) {
  patchCase(caseId, (c) => ({ ...c, status, timeline: [...c.timeline, { id: uid('t'), time: nowIso(), title: `Status → ${status}`, detail: `Changed by ${author}`, kind: 'status' }] }));
}
export function setAssignee(caseId: string, assignee: string) { patchCase(caseId, (c) => ({ ...c, assignee })); }
export const ANALYSTS = ['Aiman', 'Sara', 'Bilal', 'Unassigned'];
