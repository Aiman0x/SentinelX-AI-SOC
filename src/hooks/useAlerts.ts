import { useApp } from '../context/AppContext';
import { alertsStore, getAlerts } from '../services/alertsService';
import { isBackendConfigured } from '../services/apiClient';
import type { Alert } from '../types/alert';
import { useData } from './useData';
import { useLocalStore } from './useLocalStore';

/** Alerts from the backend when configured, otherwise from local demo data (clearly flagged by `isDemo`). */
export function useAlerts(view: 'active' | 'archived' = 'active'): { alerts: Alert[]; loading: boolean; error: string | null; reload: () => void; isDemo: boolean } {
  const { refreshKey } = useApp();
  const state = useData(() => getAlerts(view), [refreshKey, view]);
  const local = useLocalStore(alertsStore);
  const alerts = isBackendConfigured ? state.data?.data ?? [] : [];
  return { alerts, loading: state.loading, error: state.error, reload: state.reload, isDemo: false };
}
