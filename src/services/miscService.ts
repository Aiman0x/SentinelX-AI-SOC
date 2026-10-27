import { demoAssets } from '../data/demoAssets';
import { demoAudit } from '../data/demoAudit';
import { demoRules } from '../data/demoDetectionRules';
import { demoPlaybooks } from '../data/demoPlaybooks';
import { buildTrend, type TrendRange } from '../data/demoTrends';
import type { Asset } from '../types/asset';
import type { DetectionRule } from '../types/extra';
import { apiGet, delay, isBackendConfigured } from './apiClient';
import { createLocalStore } from './localStore';

/** Assets and rules are stored locally in the prototype. Adding an asset does NOT scan or contact it. */
export const assetsStore = createLocalStore<Asset[]>('sentinelx.demo.assets.v1', () => structuredClone(demoAssets));
export const rulesStore = createLocalStore<DetectionRule[]>('sentinelx.demo.rules.v1', () => structuredClone(demoRules));

export function addAsset(a: Omit<Asset, 'id' | 'monitoring' | 'addedBy'>): Asset {
  const nums = assetsStore.getSnapshot().map((x) => Number(x.id.split('-')[1]) || 0);
  const asset: Asset = { ...a, id: `AST-${String(Math.max(0, ...nums) + 1).padStart(3, '0')}`, monitoring: 'registered', addedBy: 'user' };
  assetsStore.set([asset, ...assetsStore.getSnapshot()]);
  return asset;
}

export function addRule(r: Omit<DetectionRule, 'id' | 'status' | 'maturity' | 'lastTested' | 'mitre'> & { mitre?: string[] }): DetectionRule {
  const nums = rulesStore.getSnapshot().map((x) => Number(x.id.split('-')[1]) || 0);
  const rule: DetectionRule = { ...r, mitre: r.mitre ?? [], id: `SXR-${String(Math.max(0, ...nums) + 1).padStart(3, '0')}`, status: 'draft', maturity: 'unvalidated' };
  rulesStore.set([rule, ...rulesStore.getSnapshot()]);
  return rule;
}

export async function loadPlaybooks() {
  await delay(250);
  return demoPlaybooks;
}
export async function loadAudit() {
  if (isBackendConfigured) return apiGet<import('../types/extra').AuditRecord[]>('/api/audit');
  await delay(250);
  return demoAudit;
}
export async function loadTrend(range: TrendRange) {
  await delay(200);
  return buildTrend(range);
}

export function resetAllDemoData() {
  ['alerts', 'cases', 'assets', 'rules', 'integrations'].forEach((k) => {
    try {
      window.localStorage.removeItem(`sentinelx.demo.${k}.v1`);
    } catch {
      /* ignore */
    }
  });
  window.location.reload();
}
