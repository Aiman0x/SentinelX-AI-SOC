import { demoCases } from '../data/demoCases';
import type { Alert } from '../types/alert';
import type { CaseNote, CaseStatus, SecurityCase } from '../types/case';
import { apiGet, delay, isBackendConfigured } from './apiClient';
import { rowsFrom, mapCase } from './backendMappers';
import { createLocalStore } from './localStore';
import { updateAlert } from './alertsService';

export const casesStore = createLocalStore<SecurityCase[]>('sentinelx.demo.cases.v1', () => structuredClone(demoCases));
const nowIso = () => new Date().toISOString();
const uid = (p: string) => `${p}-${Math.random().toString(36).slice(2, 8)}`;

export async function loadCases(): Promise<SecurityCase[]> {
  if (isBackendConfigured) return rowsFrom(await apiGet<unknown>('/api/cases')).map(mapCase);
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
