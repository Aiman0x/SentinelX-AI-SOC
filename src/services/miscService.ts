export type TrendRange = '24h' | '7d' | '30d';
export interface TrendPoint { label: string; critical: number; high: number; medium: number; low: number; }
import type { Asset } from '../types/asset';
import type { Severity } from '../types/alert';
import type { DetectionRule, AuditRecord, InvestigationRecord, EvidenceRecord, Playbook } from '../types/extra';
import { apiGet, delay, isBackendConfigured } from './apiClient';
import { rowsFrom, mapAsset, mapAudit, mapInvestigation, mapEvidence } from './backendMappers';
import { createLocalStore } from './localStore';

export const assetsStore = createLocalStore<Asset[]>('sentinelx.live.assets.v1', () => []);
export const rulesStore = createLocalStore<DetectionRule[]>('sentinelx.live.rules.v1', () => []);

export async function loadAssets(): Promise<Asset[]> {
  if (isBackendConfigured) return rowsFrom(await apiGet<unknown>('/api/assets')).map(mapAsset);
  return [];
}
export async function loadRules(): Promise<DetectionRule[]> {
  if (isBackendConfigured) {
    const payload = await apiGet<{ data?: Array<Record<string, unknown>> }>('/api/detections/rules');
    return (Array.isArray(payload.data) ? payload.data : []).map((row) => {
      let mitreValues: unknown = row.mitre ?? row.mitre_json ?? [];
      if (typeof mitreValues === 'string') {
        try { mitreValues = JSON.parse(mitreValues); } catch { mitreValues = []; }
      }
      const mitre = Array.isArray(mitreValues)
        ? mitreValues.map((item) => typeof item === 'string' ? item : String((item as Record<string, unknown>)?.id ?? '')).filter(Boolean)
        : [];
      const ruleType = String(row.rule_type ?? 'builtin');
      const enabled = row.enabled !== false && row.enabled !== 0;
      const key = String(row.ruleKey ?? row.rule_key ?? row.id ?? 'rule-unknown');
      return {
        id: key,
        name: String(row.title ?? key),
        description: String(row.description ?? 'No rule description recorded.'),
        category: ruleType === 'sigma' ? 'Custom Sigma' : 'Built-in detection',
        severity: (['critical', 'high', 'medium', 'low'].includes(String(row.severity)) ? String(row.severity) : 'medium') as Severity,
        source: ruleType === 'sigma' ? 'Custom Sigma rule' : 'SentinelX Detection Engine',
        mitre,
        status: enabled ? 'enabled' : 'disabled',
        maturity: ruleType === 'builtin' ? 'validated' : 'unvalidated',
        requiredEvidence: ['Tenant-scoped normalized security event', 'Original event snapshot and timestamp'],
        logic: String(row.sigma_yaml ?? row.description ?? 'Built-in rule evaluated by the SentinelX detection engine.'),
        response: ['Validate the event against the originating host or security platform.', 'Review related events before taking response action.'],
      } satisfies DetectionRule;
    });
  }
  return [];
}
export async function loadEvidence(): Promise<EvidenceRecord[]> {
  if (isBackendConfigured) return rowsFrom(await apiGet<unknown>('/api/evidence')).map(mapEvidence);
  await delay(200); return [];
}
export async function loadInvestigations(): Promise<InvestigationRecord[]> {
  if (isBackendConfigured) return rowsFrom(await apiGet<unknown>('/api/investigations')).map(mapInvestigation);
  await delay(200); return [];
}
export async function loadAudit(): Promise<AuditRecord[]> {
  if (isBackendConfigured) return rowsFrom(await apiGet<unknown>('/api/audit')).map(mapAudit);
  return [];
}
export function addAsset(a: Omit<Asset, 'id' | 'monitoring' | 'addedBy'>): Asset {
  const nums = assetsStore.getSnapshot().map((x) => Number(x.id.split('-')[1]) || 0);
  const asset: Asset = { ...a, id: `AST-${String(Math.max(0, ...nums) + 1).padStart(3, '0')}`, monitoring: 'registered', addedBy: 'user' };
  assetsStore.set([asset, ...assetsStore.getSnapshot()]); return asset;
}
export function addRule(r: Omit<DetectionRule, 'id' | 'status' | 'maturity' | 'lastTested' | 'mitre'> & { mitre?: string[] }): DetectionRule {
  const nums = rulesStore.getSnapshot().map((x) => Number(x.id.split('-')[1]) || 0);
  const rule: DetectionRule = { ...r, mitre: r.mitre ?? [], id: `SXR-${String(Math.max(0, ...nums) + 1).padStart(3, '0')}`, status: 'draft', maturity: 'unvalidated' };
  rulesStore.set([rule, ...rulesStore.getSnapshot()]); return rule;
}
export async function loadPlaybooks(): Promise<Playbook[]> { return []; }
export async function loadTrend(range: TrendRange): Promise<TrendPoint[]> {
  if (!isBackendConfigured) return [];
  const payload = await apiGet<{ data?: TrendPoint[] }>(`/api/events/summary?range=${range}`);
  return Array.isArray(payload.data) ? payload.data : [];
}
export function resetAllDemoData() {
  ['alerts', 'cases', 'assets', 'rules', 'integrations'].forEach((k) => { try { window.localStorage.removeItem(`sentinelx.demo.${k}.v1`); } catch { /* ignore */ } });
  window.location.reload();
}
