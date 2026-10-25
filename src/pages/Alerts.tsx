import { RefreshCw } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { AlertFilters, emptyAlertFilters, type AlertFilterState } from '../components/alerts/AlertFilters';
import { AlertTable, type AlertSortKey } from '../components/alerts/AlertTable';
import { Pagination, Panel } from '../components/common/Controls';
import { EmptyState, ErrorState, LoadingState } from '../components/common/EmptyState';
import { PageHeader } from '../components/layout/PageHeader';
import { useApp } from '../context/AppContext';
import { useAlerts } from '../hooks/useAlerts';
import { severityRank } from '../utils/severity';

const PAGE_SIZE = 8;

export default function Alerts() {
  const { alerts, loading, error, reload } = useAlerts();
  const { openAlert, refresh, toast } = useApp();
  const [params, setParams] = useSearchParams();
  const [filters, setFilters] = useState<AlertFilterState>({ ...emptyAlertFilters, q: params.get('q') ?? '' });
  const [sortKey, setSortKey] = useState<AlertSortKey>('timestamp');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(1);

  // Pick up ?q= from the global search box.
  useEffect(() => {
    const q = params.get('q');
    if (q !== null) {
      setFilters((f) => ({ ...f, q }));
      setPage(1);
      params.delete('q');
      setParams(params, { replace: true });
    }
  }, [params, setParams]);

  const sources = useMemo(() => [...new Set(alerts.map((a) => a.source))].sort(), [alerts]);

  const filtered = useMemo(() => {
    const q = filters.q.trim().toLowerCase();
    const cutoff = filters.date === 'all' ? 0 : Date.now() - Number(filters.date) * 3600000;
    const list = alerts.filter((a) =>
      (filters.severity === 'all' || a.severity === filters.severity) &&
      (filters.status === 'all' || a.status === filters.status) &&
      (filters.source === 'all' || a.source === filters.source) &&
      +new Date(a.timestamp) >= cutoff &&
      (!q || [a.id, a.eventId, a.ruleName, a.asset, a.sourceIp, a.source].some((v) => v.toLowerCase().includes(q))),
    );
    const dir = sortDir === 'asc' ? 1 : -1;
    return [...list].sort((a, b) => {
      if (sortKey === 'severity') return (severityRank[a.severity] - severityRank[b.severity]) * dir;
      if (sortKey === 'timestamp') return (+new Date(a.timestamp) - +new Date(b.timestamp)) * dir;
      return String(a[sortKey]).localeCompare(String(b[sortKey])) * dir;
    });
  }, [alerts, filters, sortKey, sortDir]);

  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, pages);
  const rows = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  const onSort = (k: AlertSortKey) => {
    if (k === sortKey) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setSortKey(k); setSortDir(k === 'timestamp' || k === 'severity' ? 'desc' : 'asc'); }
  };

  return (
    <>
      <PageHeader
        title="Security Alerts"
        subtitle="Search, filter and triage detections."
        actions={<button className="btn" onClick={() => { refresh(); reload(); toast('Alerts reloaded.', 'info'); }}><RefreshCw className="h-3.5 w-3.5" /> Refresh</button>}
      />
      <Panel>
        <AlertFilters value={filters} onChange={(f) => { setFilters(f); setPage(1); }} sources={sources} />
        {loading ? <LoadingState label="Loading alerts…" /> : error ? <ErrorState message={error} onRetry={reload} /> : filtered.length === 0 ? (
          <EmptyState title="No alerts match your filters" description="Try clearing a filter or widening the date range." />
        ) : (
          <>
            <AlertTable variant="full" alerts={rows} onOpen={openAlert} sortKey={sortKey} sortDir={sortDir} onSort={onSort} />
            <Pagination page={safePage} pageSize={PAGE_SIZE} total={filtered.length} onPage={setPage} />
          </>
        )}
      </Panel>
    </>
  );
}
