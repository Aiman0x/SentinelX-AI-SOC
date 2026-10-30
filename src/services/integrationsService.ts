import { demoIntegrations } from '../data/demoIntegrations';
import type { Integration, TestResult } from '../types/integration';
import { apiGet, apiPost, delay, isBackendConfigured } from './apiClient';
import { mapIntegrationRows } from './backendMappers';
import { createLocalStore } from './localStore';

interface SavedConfig { values: Record<string, string>; savedAt: string; lastTest?: TestResult; }
export const integrationConfigStore = createLocalStore<Record<string, SavedConfig>>('sentinelx.demo.integrations.v1', () => ({}));
export function getIntegrations(): Integration[] { return demoIntegrations; }
export async function loadIntegrations(): Promise<Integration[]> {
  if (isBackendConfigured) return mapIntegrationRows(await apiGet<unknown>('/api/integrations'));
  await delay(250); return getIntegrations();
}
export async function saveIntegrationConfig(integration: Integration, values: Record<string, string>) {
  if (isBackendConfigured) {
    const result = await apiPost<{ saved: boolean }>(`/api/integrations/${integration.id}/config`, { values });
    if (!result.saved) throw new Error('Backend did not confirm configuration save.');
    return;
  }
  const safe: Record<string, string> = {};
  for (const f of integration.fields) if (!f.secret && values[f.key]) safe[f.key] = values[f.key];
  const all = integrationConfigStore.getSnapshot();
  integrationConfigStore.set({ ...all, [integration.id]: { values: safe, savedAt: new Date().toISOString(), lastTest: all[integration.id]?.lastTest } });
}
export async function testConnection(integration: Integration): Promise<TestResult> {
  const at = new Date().toISOString();
  let result: TestResult;
  if (!isBackendConfigured) {
    await delay(500);
    result = { ok: false, unavailable: true, at, message: 'Cannot verify: no SentinelX backend is configured. Health checks must run server-side.' };
  } else {
    try {
      const res = await apiPost<{ ok: boolean; message?: string }>(`/api/integrations/${integration.id}/test`, {});
      result = { ok: !!res.ok, at, message: res.message ?? (res.ok ? 'Health check passed.' : 'Health check failed.') };
    } catch (e) { result = { ok: false, at, message: e instanceof Error ? e.message : 'Health check failed.' }; }
  }
  const all = integrationConfigStore.getSnapshot();
  integrationConfigStore.set({ ...all, [integration.id]: { values: all[integration.id]?.values ?? {}, savedAt: all[integration.id]?.savedAt ?? '', lastTest: result } });
  return result;
}
