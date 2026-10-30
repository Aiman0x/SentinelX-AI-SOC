import { apiGet, isBackendConfigured } from './apiClient';
import { rowsFrom } from './backendMappers';

export interface WindowsTelemetryEvent {
  id: string;
  eventId: string;
  eventType: string;
  eventTime: string;
  receivedAt: string;
  host: string;
  username: string;
  sourceIp: string;
  source: string;
  dataOrigin: string;
  validationStatus: string;
  notes: string;
  raw: string;
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
    id: String(row.id ?? index),
    eventId: value(row, 'Source Event ID', value(row, 'Event ID')),
    eventType: value(row, 'Event Type'),
    eventTime: value(row, 'Event Time'),
    receivedAt: value(row, 'Received At'),
    host: value(row, 'Host'),
    username: value(row, 'Username'),
    sourceIp: value(row, 'Source IP'),
    source: value(row, 'Source Integration'),
    dataOrigin: value(row, 'Data Origin'),
    validationStatus: value(row, 'Validation Status'),
    notes: value(row, 'Notes', ''),
    raw: value(row, 'Normalized Event JSON', ''),
  }));
}
