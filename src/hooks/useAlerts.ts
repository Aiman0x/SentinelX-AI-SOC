import { useApp } from '../context/AppContext';
import { getAlerts } from '../services/alertsService';
import { isBackendConfigured } from '../services/apiClient';
import type { Alert } from '../types/alert';
import { useData } from './useData';

/** Live backend security alerts, separated into active and archived retention windows. */
export function useAlerts(view: 'active' | 'archived' = 'active'): { alerts: Alert[]; loading: boolean; error: string | null; reload: () => void; isDemo: boolean } {
  const { refreshKey } = useApp();
  const state = useData(() => getAlerts(view), [refreshKey, view]);
  const alerts = isBackendConfigured ? state.data?.data ?? [] : [];
  return { alerts, loading: state.loading, error: state.error, reload: state.reload, isDemo: false };
}
