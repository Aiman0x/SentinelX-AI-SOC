import { apiGet, isBackendConfigured } from './apiClient';

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
  severity: string;
  dataOrigin: string;
  message: string;
  raw: string;
}

type SecurityEventRow = {
  id?: string;
  event_id?: string;
  source?: string;
  event_type?: string;
  severity?: string;
  observed_at?: string;
  received_at?: string;
  host?: string | null;
  username?: string | null;
  source_ip?: string | null;
  message?: string;
  normalized?: Record<string, unknown>;
};

const text = (value: unknown, fallback = '—'): string =>
  value === undefined || value === null || value === '' ? fallback : String(value);

export async function getWindowsTelemetry(view: 'active' | 'archived' = 'active', source = 'windows'): Promise<WindowsTelemetryEvent[]> {
  if (!isBackendConfigured) throw new Error('SentinelX backend is not configured.');
  const params = new URLSearchParams({ limit: '100', status: view });
  if (source !== 'all') params.set('source', source);
  const payload = await apiGet<{ data?: SecurityEventRow[] }>(`/api/events?${params.toString()}`);
  const rows = Array.isArray(payload?.data) ? payload.data : [];
  return rows.map((row, index) => {
    const normalized = row.normalized && typeof row.normalized === 'object' ? row.normalized : {};
    const eventData = normalized.eventData && typeof normalized.eventData === 'object'
      ? normalized.eventData as Record<string, unknown> : {};
    const windowsId = eventData.EventID ?? eventData.event_id ?? normalized.eventCode ?? '';
    const sourceEventId = normalized.eventId ?? row.event_id ?? '';
    return {
      id: text(row.id, String(index)),
      eventId: text(windowsId || sourceEventId),
      eventType: text(normalized.eventType ?? row.event_type),
      eventTime: text(row.observed_at),
      receivedAt: text(row.received_at),
      host: text(row.host ?? normalized.host),
      username: text(row.username ?? normalized.username),
      sourceIp: text(row.source_ip ?? normalized.sourceIp),
      source: text(row.source ?? normalized.sourceIntegration),
      severity: text(row.severity ?? normalized.severity, 'unknown'),
      dataOrigin: text(normalized.dataOrigin, 'UNVERIFIED'),
      message: text(row.message ?? normalized.message, ''),
      raw: JSON.stringify(normalized),
    };
  });
}
