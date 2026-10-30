import { useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Select } from '../components/common/Controls';
import { EmptyState, ErrorState, LoadingState } from '../components/common/EmptyState';
import { InvestigationWorkspace } from '../components/investigation/InvestigationWorkspace';
import { PageHeader } from '../components/layout/PageHeader';
import { useAlerts } from '../hooks/useAlerts';
import { severityRank } from '../utils/severity';
import { useData } from '../hooks/useData';
import { loadEvidence, loadInvestigations } from '../services/miscService';
import { isBackendConfigured } from '../services/apiClient';
import { formatDateTime } from '../utils/formatDate';

export default function Investigation() {
  const { alerts, loading, error, reload } = useAlerts();
  const backendInvestigations = useData(loadInvestigations);
  const backendEvidence = useData(loadEvidence);
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
      {isBackendConfigured ? (
        <>
          <div className="mb-4 rounded-lg border border-sx-gold/25 bg-sx-gold/5 p-3 text-xs text-sx-gold/90">
            These are Activepieces correlation investigations, not a verified autonomous AI verdict. Findings remain candidates and require analyst review. The AI model and external tool execution are not enabled in this foundation phase.
          </div>
          {backendInvestigations.loading ? <div className="panel"><LoadingState label="Loading backend investigations…" /></div> : backendInvestigations.error ? <div className="panel"><ErrorState message={backendInvestigations.error} onRetry={backendInvestigations.reload} /></div> : (backendInvestigations.data ?? []).length === 0 ? (
            <div className="panel"><EmptyState title="No backend investigations" description="The backend has not produced any correlation records yet." /></div>
          ) : (
            <div className="space-y-3">
              {(backendInvestigations.data ?? []).map((item) => (
                <section key={item.id} className="panel p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div><div className="mono text-[10px] text-sx-gold">{item.id}</div><h2 className="mt-1 text-sm font-semibold">{item.caseId}</h2><p className="mt-1 text-[11px] text-sx-mute">{formatDateTime(item.createdAt)}</p></div>
                    <div className="flex flex-wrap gap-2"><span className="rounded border border-sx-line px-2 py-1 text-[10px]">{item.status}</span><span className="rounded border border-sx-line px-2 py-1 text-[10px]">{item.dataOrigin}</span><span className="rounded border border-sx-line px-2 py-1 text-[10px]">Confidence {item.confidence}%</span></div>
                  </div>
                  <p className="mt-3 text-xs leading-5">{item.narrative}</p>
                  <div className="mt-3 grid gap-3 text-[11px] sm:grid-cols-3">
                    <div><div className="label">Events / findings</div>{item.eventCount} events · {item.findingCount} findings</div>
                    <div><div className="label">Hosts / accounts</div>{item.hosts.join(', ') || '—'} / {item.accounts.join(', ') || '—'}</div>
                    <div><div className="label">Source IPs</div>{item.sourceIps.join(', ') || '—'}</div>
                  </div>
                  {item.signals.length > 0 && <div className="mt-3"><div className="label">Correlation signals</div><ul className="list-disc space-y-1 pl-4 text-xs">{item.signals.map((signal) => <li key={signal}>{signal}</li>)}</ul></div>}
                  {item.eventIds.length > 0 && <div className="mt-3"><div className="label">Related event IDs</div><p className="mono break-all text-[10px] text-sx-mute">{item.eventIds.join(', ')}</p></div>}
                </section>
              ))}
            </div>
          )}
          <section className="mt-6 space-y-3">
            <div><h2 className="text-sm font-semibold">Evidence references</h2><p className="text-[11px] text-sx-mute">Records returned by the Activepieces evidence workflow; excerpts are displayed as stored and are not independently validated here.</p></div>
            {backendEvidence.loading ? <div className="panel"><LoadingState label="Loading evidence references…" /></div> : backendEvidence.error ? <div className="panel"><ErrorState message={backendEvidence.error} onRetry={backendEvidence.reload} /></div> : (backendEvidence.data ?? []).length === 0 ? <div className="panel"><EmptyState title="No evidence references" description="No evidence records are currently available." /></div> : (
              <div className="space-y-2">
                {(backendEvidence.data ?? []).map((evidence) => (
                  <article key={evidence.id} className="panel p-3">
                    <div className="flex flex-wrap items-start justify-between gap-2"><div><div className="mono text-[10px] text-sx-gold">{evidence.id}</div><div className="mt-1 text-xs font-medium">{evidence.toolName} · {evidence.stepName}</div><div className="text-[10px] text-sx-mute">Case {evidence.caseId} · {evidence.sourceIntegration}</div></div><div className="flex flex-wrap gap-1.5"><span className="rounded border border-sx-line px-2 py-1 text-[10px]">{evidence.executionStatus}</span><span className="rounded border border-sx-line px-2 py-1 text-[10px]">{evidence.dataOrigin}</span></div></div>
                    <p className="mt-2 whitespace-pre-wrap break-words text-xs text-sx-mute">{evidence.excerpt.slice(0, 600)}{evidence.excerpt.length > 600 ? '…' : ''}</p>
                    <div className="mt-2 flex flex-wrap justify-between gap-2 text-[10px] text-sx-mute"><span>{evidence.classification} · relevance {evidence.relevance}</span><span>{formatDateTime(evidence.collectedAt)}</span></div>
                    <p className="mono mt-1 break-all text-[9px] text-sx-mute">SHA-256: {evidence.evidenceHash}</p>
                  </article>
                ))}
              </div>
            )}
          </section>
        </>
      ) : loading ? <div className="panel"><LoadingState label="Loading investigation data…" /></div> : error ? <div className="panel"><ErrorState message={error} onRetry={reload} /></div> : !primary ? (
        <div className="panel"><EmptyState title="Nothing to investigate" description="No alerts are available. Connect a data source or use demo mode." /></div>
      ) : (
        <InvestigationWorkspace primary={primary} all={alerts} />
      )}
    </>
  );
}
