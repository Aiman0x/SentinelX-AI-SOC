import { API_BASE_URL, apiGet, isBackendConfigured } from './apiClient';

export type FeatureStatus = 'connected' | 'configured_unverified' | 'pending' | 'not_configured' | 'unavailable' | 'demo';

export interface BackendFeatureStatus {
  status: FeatureStatus;
  source?: string;
  detail?: string;
}

export interface BackendStatus {
  overall: 'connected' | 'partial' | 'pending' | 'unavailable' | string;
  features: Record<string, BackendFeatureStatus>;
}

export type BackendStatusView =
  | { state: 'demo'; label: 'DEMO MODE'; detail: string }
  | { state: 'unavailable'; label: 'BACKEND UNAVAILABLE'; detail: string }
  | { state: 'partial'; label: 'PARTIAL INTEGRATION'; detail: string }
  | { state: 'connected'; label: 'BACKEND CONNECTED'; detail: string };

export async function getBackendStatusView(): Promise<BackendStatusView> {
  if (!isBackendConfigured) {
    return { state: 'demo', label: 'DEMO MODE', detail: 'No backend URL is configured.' };
  }

  try {
    const status = await apiGet<BackendStatus>('/api/status');
    const featureStatuses = Object.values(status.features ?? {}).map((item) => item.status);
    const allConnected = status.overall === 'connected' && featureStatuses.length > 0 && featureStatuses.every((item) => item === 'connected');
    if (allConnected) {
      return { state: 'connected', label: 'BACKEND CONNECTED', detail: 'All reported features are connected.' };
    }
    return {
      state: 'partial',
      label: 'PARTIAL INTEGRATION',
      detail: 'Some features are pending or unverified. Check each screen’s data-source status.',
    };
  } catch (error) {
    return {
      state: 'unavailable',
      label: 'BACKEND UNAVAILABLE',
      detail: error instanceof Error ? error.message : 'Could not verify backend status.',
    };
  }
}

export function backendBaseUrlConfigured(): boolean {
  return Boolean(API_BASE_URL);
}
