import { Bug, Globe, Network, Radar, ScanSearch, Settings2, Shield, TestTube2, Workflow, Search, Plus, Server, ChevronDown, type LucideIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Field, Panel } from '../components/common/Controls';
import { ErrorState, LoadingState } from '../components/common/EmptyState';
import { Modal } from '../components/common/Modal';
import { StatusBadge } from '../components/common/StatusBadge';
import { PageHeader } from '../components/layout/PageHeader';
import { useApp } from '../context/AppContext';
import { useData } from '../hooks/useData';
import { loadIntegrations, saveIntegrationConfig, testConnection, queryIntegration, disconnectIntegration } from '../services/integrationsService';
import type { Integration, IntegrationField } from '../types/integration';
import { formatDateTime } from '../utils/formatDate';
import { isBackendConfigured } from '../services/apiClient';
import { HostCollectors } from '../components/integrations/HostCollectors';

const icons: Record<string, LucideIcon> = {
  activepieces: Workflow, wazuh: Shield, windows_security: Shield, sysmon: Radar, suricata: Network, zeek: Network,
  virustotal: ScanSearch, abuseipdb: Shield, urlscan: Globe, clamav: Bug, yara: ScanSearch,
};
const categories = ['All tools', 'SIEM', 'Endpoint', 'Network', 'Threat Intelligence', 'Malware', 'Orchestration'];
const initialQuery = (fields: IntegrationField[] = []) => Object.fromEntries(fields.map(f => [f.key, f.key === 'limit' ? '25' : f.key === 'resource' ? 'agents' : f.key === 'type' ? 'ip' : '']));
const FieldControl = ({ field, value, onChange, disabled = false }: { field: IntegrationField; value: string; onChange: (v: string) => void; disabled?: boolean }) => {
  if (field.key === 'type') return <select className="input mono" value={value || 'ip'} onChange={e => onChange(e.target.value)}><option value="ip">IP address</option><option value="domain">Domain</option><option value="url">URL</option><option value="hash">File hash</option></select>;
  if (field.key === 'resource') return <select className="input mono" value={value || 'agents'} onChange={e => onChange(e.target.value)}><option value="agents">List agents</option><option value="agent">Get one agent</option><option value="manager">Manager info</option><option value="alerts">Recent Wazuh alerts</option></select>;
  return <input className="input" type={field.type === 'password' || field.secret ? 'password' : field.type === 'url' ? 'url' : 'text'} value={value ?? ''} placeholder={field.placeholder} onChange={e => onChange(e.target.value)} autoComplete="off" disabled={disabled} />;
};

export default function Integrations() {
  const { data, loading, error, reload } = useData(loadIntegrations);
  const { toast } = useApp();
  const [editing, setEditing] = useState<Integration | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [testing, setTesting] = useState<string | null>(null);
  const [querying, setQuerying] = useState<string | null>(null);
  const [disconnecting, setDisconnecting] = useState<string | null>(null);
  const [queryValues, setQueryValues] = useState<Record<string, Record<string, string>>>({});
  const [queryResults, setQueryResults] = useState<Record<string, string>>({});
  const [expandedQuery, setExpandedQuery] = useState<string | null>(null);
  const [showCatalog, setShowCatalog] = useState(false);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('All tools');
  const [showCollectors, setShowCollectors] = useState(true);

  const tools = data ?? [];
  const connectedTools = tools.filter(i => i.configured || i.verified || i.state === 'connected');
  const catalogTools = useMemo(() => tools.filter(i => {
    const matchesCategory = category === 'All tools' || i.category === category;
    const term = search.trim().toLowerCase();
    const matchesSearch = !term || [i.name, i.category, i.purpose].some(v => v.toLowerCase().includes(term));
    return matchesCategory && matchesSearch;
  }), [tools, category, search]);

  const configure = (i: Integration) => { setEditing(i); setValues({}); };
  const save = async () => {
    if (!editing) return;
    try {
      await saveIntegrationConfig(editing, values);
      toast(`${editing.name}: setup saved. Run Test connection to verify it.`, 'success');
      setEditing(null); setValues({});
      await reload();
    } catch (e) { toast(e instanceof Error ? e.message : 'Configuration could not be saved.', 'warn'); }
  };
  const test = async (i: Integration) => {
    setTesting(i.id);
    const r = await testConnection(i);
    setTesting(null);
    toast(`${i.name}: ${r.message}`, r.ok ? 'success' : 'warn');
    if (isBackendConfigured) await reload();
  };
  const disconnect = async (i: Integration) => {
    setDisconnecting(i.id);
    try {
      await disconnectIntegration(i);
      toast(`${i.name}: disconnected.`, 'success');
      await reload();
    } catch (e) { toast(e instanceof Error ? e.message : 'Could not disconnect tool.', 'warn'); }
    finally { setDisconnecting(null); }
  };
  const runQuery = async (i: Integration) => {
    setQuerying(i.id);
    try {
      const result = await queryIntegration(i, queryValues[i.id] ?? {});
      setQueryResults(prev => ({ ...prev, [i.id]: JSON.stringify(result, null, 2) }));
      toast(`${i.name}: query completed.`, 'success');
    } catch (e) { toast(e instanceof Error ? e.message : 'Query failed.', 'warn'); }
    finally { setQuerying(null); }
  };
  const setQueryField = (id: string, key: string, value: string) => setQueryValues(prev => ({ ...prev, [id]: { ...(prev[id] ?? {}), [key]: value } }));

  const toolCard = (i: Integration, compact = false) => {
    const Icon = icons[i.id] ?? Shield;
    const querySchema = i.schema?.query;
    const canTest = isBackendConfigured && (i.configured || i.id === 'activepieces' || ['wazuh', 'windows_security', 'sysmon', 'suricata', 'zeek', 'clamav', 'yara'].includes(i.id));
    return (
      <Panel key={i.id} bodyClass={compact ? 'flex h-full flex-col p-3' : 'flex h-full flex-col p-4'} className="flex flex-col">
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-sx-gold/25 bg-sx-gold/5"><Icon className="h-5 w-5 text-sx-gold" aria-hidden /></div>
            <div className="min-w-0"><div className="text-sm font-semibold">{i.name}</div><div className="text-[11px] text-sx-mute">{i.category}</div></div>
          </div>
          <StatusBadge value={i.state} />
        </div>
        <p className="mt-3 flex-1 text-xs leading-5 text-sx-mute">{i.purpose}</p>
        <div className="mt-3 border-t border-sx-line pt-3 text-[11px]">
          <div className="flex items-center justify-between gap-2"><span className="text-sx-mute">Setup</span><span className={i.verified ? 'text-sx-green' : i.configured ? 'text-sx-warn' : 'text-sx-mute'}>{i.verified ? 'Connected · verified' : i.configured ? 'Saved · needs test' : 'Not connected'}</span></div>
          {i.lastHealthCheck && <div className="mt-1 flex justify-between gap-2"><span className="text-sx-mute">Last checked</span><span className="mono text-sx-mute">{formatDateTime(i.lastHealthCheck)}</span></div>}
          {i.capabilities?.length ? <p className="mt-2 text-[10px] text-sx-mute">{i.capabilities.join(' · ')}</p> : null}
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {i.fields.length > 0 ? <button className="btn flex-1" onClick={() => configure(i)} disabled={!isBackendConfigured}><Settings2 className="h-3.5 w-3.5" />{i.configured ? 'Edit setup' : 'Connect'}</button> : <div className="flex flex-1 items-center justify-center rounded-lg border border-sx-line px-2 text-[10px] text-sx-mute">{i.id === 'wazuh' ? 'Connect below' : 'Managed by SentinelX'}</div>}
          <button className="btn btn-gold flex-1" onClick={() => void test(i)} disabled={!canTest || testing === i.id}><TestTube2 className="h-3.5 w-3.5" />{testing === i.id ? 'Testing…' : 'Test'}</button>
          {i.configured && <button className="btn" onClick={() => void disconnect(i)} disabled={disconnecting === i.id}>{disconnecting === i.id ? '…' : 'Disconnect'}</button>}
          {querySchema?.supported && <button className="btn w-full" onClick={() => { setExpandedQuery(expandedQuery === i.id ? null : i.id); setQueryValues(prev => ({ ...prev, [i.id]: prev[i.id] ?? initialQuery(querySchema.fields) })); }}><Search className="h-3.5 w-3.5" />Advanced query</button>}
        </div>
        {expandedQuery === i.id && querySchema?.supported && (
          <details open className="mt-3 border-t border-sx-line pt-3">
            <summary className="cursor-pointer text-xs font-semibold text-sx-gold">Advanced read-only query</summary>
            <p className="mt-2 text-[10px] text-sx-mute">{querySchema.description}</p>
            {(querySchema.fields ?? []).map(f => <Field key={f.key} label={f.label} htmlFor={`q-${i.id}-${f.key}`}><FieldControl field={f} value={queryValues[i.id]?.[f.key] ?? ''} onChange={v => setQueryField(i.id, f.key, v)} /></Field>)}
            <button className="btn btn-gold mt-2 w-full" onClick={() => void runQuery(i)} disabled={querying === i.id || (!i.configured && !i.verified)}>{querying === i.id ? 'Running…' : 'Run query'}</button>
            {queryResults[i.id] && <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded border border-sx-line bg-sx-bg p-2 text-[10px]">{queryResults[i.id]}</pre>}
            {i.id === 'virustotal' && <p className="mt-2 text-[10px] text-sx-warn">Do not submit confidential or personal indicators to shared threat-intelligence services.</p>}
          </details>
        )}
      </Panel>
    );
  };

  return (
    <>
      <PageHeader title="Tools" subtitle="Connect the security tools SentinelX uses to investigate and protect your environment." />
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <div><p className="text-sm font-semibold">Your tools</p><p className="mt-1 text-xs text-sx-mute">A connection is confirmed only after a successful live test.</p></div>
        <button className="btn btn-primary px-4 py-2" onClick={() => { setShowCatalog(v => !v); setSearch(''); setCategory('All tools'); }}><Plus className="h-4 w-4" />{showCatalog ? 'Close directory' : 'Add tool'}</button>
      </div>

      {!isBackendConfigured && <div className="mb-4 rounded-lg border border-sx-gold/25 bg-sx-gold/5 p-3 text-xs text-sx-gold">Connect the SentinelX backend to save credentials and verify tools. Demo mode does not store secrets.</div>}

      {showCatalog && (
        <section className="panel mb-5 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div><h2 className="text-sm font-semibold">Tool directory</h2><p className="mt-1 text-xs text-sx-mute">Choose a tool to view its setup options.</p></div>
            <div className="relative w-full sm:w-64"><Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-sx-mute" /><input className="input pl-9" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search tools…" aria-label="Search tools" /></div>
          </div>
          <div className="my-4 flex flex-wrap gap-2">{categories.map(c => <button key={c} className={category === c ? 'btn btn-gold' : 'btn'} onClick={() => setCategory(c)}>{c}</button>)}</div>
          {loading ? <LoadingState /> : error ? <ErrorState message={error} onRetry={reload} /> : (
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {catalogTools.map(i => toolCard(i, true))}
              <div className="flex min-h-40 flex-col justify-between rounded-xl border border-dashed border-sx-line bg-sx-bg/60 p-4">
                <div className="flex items-center gap-3"><div className="flex h-10 w-10 items-center justify-center rounded-xl border border-sx-line text-sx-mute"><Server className="h-5 w-5" /></div><div><p className="text-sm font-semibold">Custom MCP server</p><p className="text-[11px] text-sx-mute">Advanced connection</p></div></div>
                <p className="mt-3 text-xs text-sx-mute">Add a compatible server by URL. Connection setup will be enabled when the backend support is ready.</p>
                <span className="mt-3 text-[10px] text-sx-gold">Coming in the next integration phase</span>
              </div>
              {!catalogTools.length && <p className="text-xs text-sx-mute">No tools match your search.</p>}
            </div>
          )}
        </section>
      )}

      {loading ? <div className="panel p-4"><LoadingState /></div> : error ? <div className="panel p-4"><ErrorState message={error} onRetry={reload} /></div> : (
        <section>
          <div className="mb-3 flex items-center justify-between"><h2 className="text-sm font-semibold">Connected and configured</h2><span className="text-[11px] text-sx-mute">{connectedTools.length} tool{connectedTools.length === 1 ? '' : 's'}</span></div>
          {connectedTools.length ? <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">{connectedTools.map(i => toolCard(i))}</div> : (
            <div className="panel flex flex-col items-center px-5 py-10 text-center">
              <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-sx-gold/25 bg-sx-gold/5 text-sx-gold"><Plus className="h-6 w-6" /></div>
              <p className="mt-3 text-sm font-semibold">No tools connected yet</p>
              <p className="mt-1 max-w-md text-xs text-sx-mute">Add your first security tool to let SentinelX collect evidence and investigate alerts.</p>
              <button className="btn btn-primary mt-4" onClick={() => setShowCatalog(true)}><Plus className="h-4 w-4" />Browse tools</button>
            </div>
          )}
        </section>
      )}

      <section className="mt-5">
        <button className="flex w-full items-center justify-between rounded-xl border border-sx-line bg-sx-panel px-4 py-3 text-left" onClick={() => setShowCollectors(v => !v)} aria-expanded={showCollectors}>
          <span><span className="block text-sm font-semibold">Host collectors</span><span className="mt-0.5 block text-[11px] text-sx-mute">Enroll Windows endpoints or a Linux Wazuh server.</span></span>
          <ChevronDown className={`h-4 w-4 text-sx-mute transition-transform ${showCollectors ? 'rotate-180' : ''}`} />
        </button>
        {showCollectors && <div className="mt-3"><HostCollectors /></div>}
      </section>

      <Modal open={!!editing} onClose={() => setEditing(null)} title={`Connect ${editing?.name ?? 'tool'}`}>
        {editing && (
          <div className="space-y-3">
            <p className="text-xs text-sx-mute">Enter the connection details for this tool. Credentials are handled by the SentinelX backend and are not shown again.</p>
            {editing.fields.map(f => <Field key={f.key} label={f.label} htmlFor={`f-${f.key}`}><FieldControl field={f} value={values[f.key] ?? ''} onChange={v => setValues(prev => ({ ...prev, [f.key]: v }))} disabled={!isBackendConfigured} />{f.required && <p className="mt-1 text-[10px] text-sx-mute">Required</p>}{f.help && <p className="mt-1 text-[10px] text-sx-mute">{f.help}</p>}</Field>)}
            <div className="flex justify-end gap-2"><button className="btn" onClick={() => setEditing(null)}>Cancel</button><button className="btn btn-primary" onClick={() => void save()} disabled={!isBackendConfigured}>Save setup</button></div>
          </div>
        )}
      </Modal>
    </>
  );
}
