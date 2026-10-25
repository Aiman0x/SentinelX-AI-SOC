import { ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useApp } from '../../context/AppContext';
import { useAlerts } from '../../hooks/useAlerts';
import { isDemoMode } from '../../services/apiClient';
import { AlertTable } from '../alerts/AlertTable';
import { Panel } from '../common/Controls';
import { EmptyState, ErrorState, LoadingState } from '../common/EmptyState';
import { DemoTag } from '../common/StatusBadge';

export function RecentAlerts() {
  const { alerts, loading, error, reload } = useAlerts();
  const { openAlert } = useApp();
  const recent = [...alerts].sort((a, b) => +new Date(b.timestamp) - +new Date(a.timestamp)).slice(0, 6);

  return (
    <Panel
      title={<span className="flex items-center gap-2">Recent Security Alerts {isDemoMode && <DemoTag />}</span>}
      right={<Link to="/alerts" className="inline-flex items-center gap-1 text-xs text-sx-gold hover:underline">View all <ArrowRight className="h-3 w-3" /></Link>}
    >
      {loading ? <LoadingState label="Loading alerts…" /> : error ? <ErrorState message={error} onRetry={reload} /> : recent.length === 0 ? (
        <EmptyState title="No alerts" description="No alerts have been received." />
      ) : (
        <AlertTable alerts={recent} onOpen={openAlert} />
      )}
    </Panel>
  );
}
