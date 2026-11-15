/**
 * API client layer.
 *
 * Live-only API client. When VITE_API_BASE_URL is missing, data-backed views stay empty rather than showing synthetic events.
 * Authentication must be handled by the backend (e.g. HttpOnly session cookies).
 * NEVER put API keys, passwords or tokens in this frontend.
 */
export const API_BASE_URL: string = ((import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '').replace(/\/$/, '');
export const isBackendConfigured: boolean = API_BASE_URL.length > 0;
export const isDemoMode: boolean = false;
export const ENVIRONMENT_LABEL: string = (import.meta.env.VITE_ENVIRONMENT_LABEL as string | undefined) || (isBackendConfigured ? 'LIVE DATA' : 'BACKEND NOT CONFIGURED');

// Purge browser-cached prototype records so old sample alerts/cases/assets cannot reappear.
try {
  for (let i = window.localStorage.length - 1; i >= 0; i -= 1) {
    const key = window.localStorage.key(i);
    if (key?.startsWith('sentinelx.demo.')) window.localStorage.removeItem(key);
  }
} catch { /* storage may be unavailable in restricted browser contexts */ }

export class BackendNotConfiguredError extends Error {
  constructor(feature = 'This feature') {
    super(`${feature} requires a SentinelX backend, which is not configured in this prototype.`);
    this.name = 'BackendNotConfiguredError';
  }
}

export interface Result<T> {
  data: T;
  /** 'demo' = local sample data, 'api' = returned by the backend. */
  source: 'demo' | 'api';
}

export const delay = (ms = 250) => new Promise<void>((r) => setTimeout(r, ms));

async function request<T>(method: 'GET' | 'POST' | 'DELETE', path: string, body?: unknown): Promise<T> {
  if (!isBackendConfigured) throw new BackendNotConfiguredError();
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method,
    credentials: 'include',
    headers: { Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    let message = `API request failed (${res.status})`;
    try {
      const payload = await res.json() as { error?: unknown; message?: unknown };
      if (typeof payload.error === 'string') message = payload.error;
      else if (typeof payload.message === 'string') message = payload.message;
    } catch { /* keep generic HTTP error */ }
    throw new Error(message);
  }
  return (await res.json()) as T;
}

export const apiGet = <T>(path: string) => request<T>('GET', path);
export const apiPost = <T>(path: string, body?: unknown) => request<T>('POST', path, body);
export const apiDelete = <T>(path: string) => request<T>('DELETE', path);
