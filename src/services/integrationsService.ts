import { demoIntegrations } from '../data/demoIntegrations';
import type { Integration, TestResult } from '../types/integration';
import { apiPost, delay, isBackendConfigured } from './apiClient';
import { createLocalStore } from './localStore';

/**
 * Only NON-SECRET configuration values are kept in the browser (prototype convenience).
 * Secret fields (passwords, API keys, webhook secrets) are discarded before saving —
 * a real backend / secrets store must hold them.
 */
interface SavedConfig {
  values: Record<string, string>;
  savedAt: string;
  lastTest?: TestResult;
}
export const integrationConfigStore = createLocalStore<Record<string, SavedConfig>>('sentinelx.demo.integrations.v1', () => ({}));

export function getIntegrations(): Integration[] {
  return demoIntegrations;
}

export async function loadIntegrations(): Promise<Integration[]> {
  await delay(250);
  return getIntegrations();
}

export function saveIntegrationConfig(integration: Integration, values: Record<string, string>) {
  const safe: Record<string, string> = {};
  for (const f of integration.fields) {
    if (!f.secret && values[f.key]) safe[f.key] = values[f.key];
  }
  const all = integrationConfigStore.getSnapshot();
  integrationConfigStore.set({ ...all, [integration.id]: { values: safe, savedAt: new Date().toISOString(), lastTest: all[integration.id]?.lastTest } });
}

/**
 * Test a connection. Without a backend this can NEVER report success —
 * it reports that the test is unavailable. Success is only returned if the backend says so.
 */
export async function testConnection(integration: Integration): Promise<TestResult> {
  const at = new Date().toISOString();
  let result: TestResult;
  if (!isBackendConfigured) {
    await delay(500);
    result = { ok: false, unavailable: true, at, message: 'Cannot verify: no SentinelX backend is configured. Health checks must run server-side.' };
  } else {
    try {
      const res = await apiPost<{ ok: boolean; message?: string }>(`/api/integrations/${integration.id}/test`);
      result = { ok: !!res.ok, at, message: res.message ?? (res.ok ? 'Health check passed.' : 'Health check failed.') };
    } catch (e) {
      result = { ok: false, at, message: e instanceof Error ? e.message : 'Health check failed.' };
    }
  }
  const all = integrationConfigStore.getSnapshot();
  integrationConfigStore.set({
    ...all,
    [integration.id]: { values: all[integration.id]?.values ?? {}, savedAt: all[integration.id]?.savedAt ?? '', lastTest: result },
  });
  return result;
}
