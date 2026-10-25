import { demoAlerts } from '../data/demoAlerts';
import type { Alert } from '../types/alert';
import { apiGet, delay, isBackendConfigured, type Result } from './apiClient';
import { createLocalStore } from './localStore';

/** Local overlay for alert changes made in the prototype (status, linked case). Demo only. */
export const alertsStore = createLocalStore<Alert[]>('sentinelx.demo.alerts.v1', () => structuredClone(demoAlerts));

export async function getAlerts(): Promise<Result<Alert[]>> {
  if (isBackendConfigured) {
    const data = await apiGet<Alert[]>('/api/alerts');
    return { data, source: 'api' };
  }
  await delay(300);
  return { data: alertsStore.getSnapshot(), source: 'demo' };
}

export function updateAlert(id: string, patch: Partial<Alert>) {
  alertsStore.set(alertsStore.getSnapshot().map((a) => (a.id === id ? { ...a, ...patch } : a)));
}

export function getAlertById(id: string | null | undefined): Alert | undefined {
  if (!id) return undefined;
  return alertsStore.getSnapshot().find((a) => a.id === id);
}
