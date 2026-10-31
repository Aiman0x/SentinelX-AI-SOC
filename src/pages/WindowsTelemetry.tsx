import { useCallback, useEffect, useMemo, useState } from 'react';
import { Play, RefreshCw, Search, ShieldAlert, Square } from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { Panel } from '../components/common/Controls';
import { EmptyState, ErrorState, LoadingState } from '../components/common/EmptyState';
import {
  getLocalCollectorStatus, getWindowsTelemetry, startLocalCollector, stopLocalCollector,
  type LocalCollectorStatus, type WindowsTelemetryEvent,
} from '../services/telemetryService';

const displayDate = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(+date) ? value : date.toLocaleString();
};

export default function WindowsTelemetry() {
  const [events, setEvents] = useState<WindowsTelemetryEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [agent, setAgent] = useState<LocalCollectorStatus | null>(null);
  const [agentError, setAgentError] = useState('Local agent is not connected.');
  const [actionBusy, setActionBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true); setError('');
    try { setEvents(await getWindowsTelemetry()); }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not load Windows telemetry.'); }
    finally { setLoading(false); }
  }, []);
  const refreshAgent = useCallback(async () => {
    try { setAgent(await getLocalCollectorStatus()); setAgentError(''); }
    catch (e) { setAgent(null); setAgentError(e instanceof Error ? e.message : 'Local agent is unavailable.'); }
  }, []);
  const runAction = async (action: 'start' | 'stop') => {
    setActionBusy(true);
    try {
      const status = action === 'start' ? await startLocalCollector() : await stopLocalCollector();
      setAgent(status); setAgentError('');
      if (action === 'start') window.setTimeout(() => void load(), 1800);
    } catch (e) {
      setAgentError(e instanceof Error ? e.message : 'Could not control the local collector.');
      await refreshAgent();
    } finally { setActionBusy(false); }
  };

  useEffect(() => { void load(); void refreshAgent(); }, [load, refreshAgent]);
  useEffect(() => {
    const timer = window.setInterval(() => { void refreshAgent(); }, 5000);
    return () => window.clearInterval(timer);
  }, [refreshAgent]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return events.filter(e => !q || [e.eventId,e.eventType,e.host,e.username,e.sourceIp,e.source,e.dataOrigin,e.validationStatus].join(' ').toLowerCase().includes(q));
  }, [events, query]);
  const realCount = events.filter(e => e.dataOrigin === 'REAL_UNVERIFIED').length;

  return <>
    <PageHeader title="Windows Telemetry" subtitle="Control the read-only local collector and inspect Windows Security events received by SentinelX."
      actions={<button className="btn" onClick={() => { void load(); void refreshAgent(); }}><RefreshCw className="h-3.5 w-3.5" /> Refresh</button>} />
    <Panel>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-sm font-semibold">Local Windows collector</h2>
          <p className="mt-1 text-xs text-sx-mute">Reads Security Event ID 4625 only · read-only · sends to the configured SentinelX intake</p>
          <p className="mt-2 text-xs">{agent ? <span className="text-emerald-400">Agent connected · collector {agent.collector}</span> : <span className="text-sx-gold">Agent offline</span>}</p>
          {agentError && <p className="mt-1 text-xs text-sx-mute">{agentError} Start the SentinelX Local Agent on this Windows PC, then refresh.</p>}
        </div>
        <div className="flex gap-2">
          <button className="btn" disabled={!agent || agent.collector === 'running' || actionBusy} onClick={() => void runAction('start')}><Play className="h-3.5 w-3.5" /> {actionBusy ? 'Working…' : 'Start collector'}</button>
          <button className="btn" disabled={!agent || agent.collector !== 'running' || actionBusy} onClick={() => void runAction('stop')}><Square className="h-3.5 w-3.5" /> Stop collector</button>
        </div>
      </div>
    </Panel>
    <div className="my-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
      <Panel><p className="text-[11px] uppercase tracking-wider text-sx-mute">Received events</p><p className="mt-1 text-2xl font-semibold">{events.length}</p></Panel>
      <Panel><p className="text-[11px] uppercase tracking-wider text-sx-mute">Real / unverified</p><p className="mt-1 text-2xl font-semibold text-sx-gold">{realCount}</p></Panel>
      <Panel><p className="text-[11px] uppercase tracking-wider text-sx-mute">Sample events</p><p className="mt-1 text-2xl font-semibold">{events.length-realCount}</p></Panel>
    </div>
    <Panel>
      <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div><h2 className="text-sm font-semibold">Incoming Windows events</h2><p className="mt-1 text-xs text-sx-mute">Latest records from SX Telemetry Intake v1 · maximum 100</p></div>
        <div className="relative w-full sm:max-w-xs"><Search className="absolute left-3 top-2.5 h-4 w-4 text-sx-mute" /><input className="input pl-9" placeholder="Search host, account, event…" value={query} onChange={e=>setQuery(e.target.value)} /></div>
      </div>
      {loading ? <LoadingState label="Loading endpoint telemetry…" /> : error ? <ErrorState message={error} onRetry={load} /> : filtered.length === 0 ?
        <EmptyState title="No Windows telemetry found" description="When the Windows collector sends events, they will appear here. This page does not generate demo events." /> :
        <div className="overflow-x-auto"><table className="w-full min-w-[900px] text-left text-xs">
          <thead><tr className="border-b border-sx-line text-[10px] uppercase tracking-wider text-sx-mute"><th className="px-3 py-3">Event time</th><th className="px-3 py-3">Event</th><th className="px-3 py-3">Host</th><th className="px-3 py-3">Username</th><th className="px-3 py-3">Source IP</th><th className="px-3 py-3">Origin / validation</th></tr></thead>
          <tbody>{filtered.map(e=><tr key={e.id} className="border-b border-sx-line/70 align-top hover:bg-sx-elev/40">
            <td className="whitespace-nowrap px-3 py-3 text-sx-mute">{displayDate(e.eventTime)}</td>
            <td className="px-3 py-3"><div className="font-medium text-sx-ink">{e.eventType}</div><div className="mt-1 font-mono text-[10px] text-sx-mute">{e.eventId}</div></td>
            <td className="px-3 py-3">{e.host}</td><td className="px-3 py-3">{e.username}</td><td className="px-3 py-3 font-mono">{e.sourceIp}</td>
            <td className="px-3 py-3"><div>{e.dataOrigin}</div><div className="mt-1 text-[10px] text-sx-gold">{e.validationStatus}</div></td>
          </tr>)}</tbody>
        </table></div>}
      <div className="mt-4 flex items-center gap-2 border-t border-sx-line pt-3 text-[10px] text-sx-mute"><ShieldAlert className="h-3.5 w-3.5 text-sx-gold" /> Real-unverified events remain quarantined until source mapping and validation are approved.</div>
    </Panel>
  </>;
}
