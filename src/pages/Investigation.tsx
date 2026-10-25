import { useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Select } from '../components/common/Controls';
import { EmptyState, ErrorState, LoadingState } from '../components/common/EmptyState';
import { InvestigationWorkspace } from '../components/investigation/InvestigationWorkspace';
import { PageHeader } from '../components/layout/PageHeader';
import { useAlerts } from '../hooks/useAlerts';
import { severityRank } from '../utils/severity';

export default function Investigation() {
  const { alerts, loading, error, reload } = useAlerts();
  const [params, setParams] = useSearchParams();
  const wanted = params.get('alert');

  const primary = useMemo(() => {
    if (alerts.length === 0) return undefined;
    return alerts.find((a) => a.id === wanted)
      ?? [...alerts].filter((a) => a.status !== 'resolved' && a.status !== 'false_positive').sort((a, b) => severityRank[b.severity] - severityRank[a.severity])[0]
      ?? alerts[0];
  }, [alerts, wanted]);

  return (
    <>
      <PageHeader
        title="Investigation Workspace"
        subtitle="Correlate evidence, build a timeline and get assistant guidance."
        actions={alerts.length > 0 && primary ? (
          <div className="w-72">
            <Select label="Select primary alert" value={primary.id} onChange={(v) => setParams({ alert: v })}
              options={alerts.map((a) => ({ value: a.id, label: `${a.id} · ${a.ruleName}` }))} />
          </div>
        ) : undefined}
      />
      {loading ? <div className="panel"><LoadingState label="Loading investigation data…" /></div> : error ? <div className="panel"><ErrorState message={error} onRetry={reload} /></div> : !primary ? (
        <div className="panel"><EmptyState title="Nothing to investigate" description="No alerts are available. Connect a data source or use demo mode." /></div>
      ) : (
        <InvestigationWorkspace primary={primary} all={alerts} />
      )}
    </>
  );
}
