import { apiGet, isBackendConfigured } from './apiClient';
import { rowsFrom } from './backendMappers';

const LOCAL_AGENT = 'http://127.0.0.1:8765';
const LOCAL_HEADERS = { Accept: 'application/json', 'Content-Type': 'application/json', 'X-SentinelX-Local-Agent': 'sentinelx-gui-v1' };

export interface LocalCollectorStatus {
  agent: 'online';
  collector: 'running' | 'stopped';
  processId: number | null;
  eventScope: string;
}

async function localAgentRequest<T>(path: string, method: 'GET' | 'POST' = 'GET'): Promise<T> {
  const response = await fetch(LOCAL_AGENT + path, {
    method, mode: 'cors', cache: 'no-store', headers: LOCAL_HEADERS,
    signal: AbortSignal.timeout(2500),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({})) as { error?: string };
    throw new Error(payload.error || 'Local agent request failed (' + response.status + ').');
  }
  return response.json() as Promise<T>;
}
export const getLocalCollectorStatus = () => localAgentRequest<LocalCollectorStatus>('/status');
export const startLocalCollector = () => localAgentRequest<LocalCollectorStatus>('/collector/start', 'POST');
export const stopLocalCollector = () => localAgentRequest<LocalCollectorStatus>('/collector/stop', 'POST');

export interface WindowsTelemetryEvent {
  id: string; eventId: string; eventType: string; eventTime: string; receivedAt: string;
  host: string; username: string; sourceIp: string; source: string; dataOrigin: string;
  validationStatus: string; notes: string; raw: string;
}
const value = (row: Record<string, unknown>, key: string, fallback = '—') => {
  const cells = row.cells && typeof row.cells === 'object' ? row.cells as Record<string, unknown> : {};
  const v = cells[key] ?? row[key];
  return v === undefined || v === null || v === '' ? fallback : String(v);
};
export async function getWindowsTelemetry(): Promise<WindowsTelemetryEvent[]> {
  if (!isBackendConfigured) throw new Error('SentinelX backend is not configured.');
  const payload = await apiGet<unknown>('/api/telemetry');
  return rowsFrom(payload).map((row, index) => ({
    id: String(row.id ?? index), eventId: value(row, 'Source Event ID', value(row, 'Event ID')),
    eventType: value(row, 'Event Type'), eventTime: value(row, 'Event Time'),
    receivedAt: value(row, 'Received At'), host: value(row, 'Host'), username: value(row, 'Username'),
    sourceIp: value(row, 'Source IP'), source: value(row, 'Source Integration'),
    dataOrigin: value(row, 'Data Origin'), validationStatus: value(row, 'Validation Status'),
    notes: value(row, 'Notes', ''), raw: value(row, 'Normalized Event JSON', ''),
  }));
}
