import type { Alert } from '../types/alert';
import { apiGet, delay, isBackendConfigured, type Result } from './apiClient';
import { rowsFrom, mapFinding } from './backendMappers';
import { createLocalStore } from './localStore';

export const alertsStore = createLocalStore<Alert[]>('sentinelx.live.alerts.v1', () => []);

export async function getAlerts(view: 'active' | 'archived' = 'active'): Promise<Result<Alert[]>> {
  if (isBackendConfigured) {
    const payload = await apiGet<unknown>(`/api/alerts?status=${view}&limit=200`);
    return { data: rowsFrom(payload).map(mapFinding), source: 'api' };
  }
  await delay(100);
  return { data: [], source: 'api' };
}

export function updateAlert(id: string, patch: Partial<Alert>) {
  alertsStore.set(alertsStore.getSnapshot().map((a) => (a.id === id ? { ...a, ...patch } : a)));
}

export function getAlertById(id: string | null | undefined): Alert | undefined {
  if (!id) return undefined;
  return alertsStore.getSnapshot().find((a) => a.id === id);
}
