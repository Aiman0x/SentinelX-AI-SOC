/**
 * API client layer.
 *
 * VITE_API_BASE_URL is public configuration only. Never put secrets or ActivePieces
 * tokens in frontend environment variables. Authentication must be implemented server-side.
 */
export const API_BASE_URL: string = ((import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '').replace(/\/$/, '');
export const isBackendConfigured: boolean = API_BASE_URL.length > 0;
/** True only when no backend URL is configured; page-level API failures are handled separately. */
export const isDemoMode: boolean = !isBackendConfigured;
export const ENVIRONMENT_LABEL: string = (import.meta.env.VITE_ENVIRONMENT_LABEL as string | undefined) || 'DEMO ENVIRONMENT';

export class BackendNotConfiguredError extends Error {
  constructor(feature = 'This feature') {
    super(`${feature} requires a SentinelX backend, which is not configured.`);
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

  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 15000);
  try {
    const res = await fetch(`${API_BASE_URL}${path}`, {
      method,
      credentials: 'include',
      signal: controller.signal,
      headers: { Accept: 'application/json', ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    const payload: unknown = await res.json().catch(() => null);
    if (!res.ok) {
      const detail = payload && typeof payload === 'object' && 'detail' in payload
        ? (payload as { detail?: unknown }).detail
        : undefined;
      const message = typeof detail === 'string'
        ? detail
        : detail && typeof detail === 'object' && 'message' in detail
          ? String((detail as { message?: unknown }).message)
          : `API request failed (${res.status})`;
      throw new Error(message);
    }
    return payload as T;
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      throw new Error('Backend request timed out. Check the connection and try again.');
    }
    if (error instanceof TypeError) {
      throw new Error('Cannot reach the SentinelX backend. Check its URL, availability and CORS configuration.');
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

export const apiGet = <T>(path: string) => request<T>('GET', path);
export const apiPost = <T>(path: string, body?: unknown) => request<T>('POST', path, body);
