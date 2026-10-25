/**
 * API client layer.
 *
 * The prototype runs in DEMO MODE: no backend, no secrets, no live telemetry.
 * When VITE_API_BASE_URL is set, services call the backend instead of using demo data.
 * Authentication must be handled by the backend (e.g. HttpOnly session cookies).
 * NEVER put API keys, passwords or tokens in this frontend.
 */
export const API_BASE_URL: string = ((import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '').replace(/\/$/, '');
export const isBackendConfigured: boolean = API_BASE_URL.length > 0;
export const isDemoMode: boolean = !isBackendConfigured;
export const ENVIRONMENT_LABEL: string = (import.meta.env.VITE_ENVIRONMENT_LABEL as string | undefined) || 'DEMO ENVIRONMENT';

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

async function request<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> {
  if (!isBackendConfigured) throw new BackendNotConfiguredError();
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method,
    credentials: 'include',
    headers: { Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`API request failed (${res.status})`);
  return (await res.json()) as T;
}

export const apiGet = <T>(path: string) => request<T>('GET', path);
export const apiPost = <T>(path: string, body?: unknown) => request<T>('POST', path, body);
