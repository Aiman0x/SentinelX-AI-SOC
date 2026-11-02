import { Bug, Globe, Network, Radar, ScanSearch, Settings2, Shield, TestTube2, Workflow, Search, type LucideIcon } from 'lucide-react';
import { useState } from 'react';
import { Field, Panel } from '../components/common/Controls';
import { ErrorState, LoadingState } from '../components/common/EmptyState';
import { Modal } from '../components/common/Modal';
import { StatusBadge } from '../components/common/StatusBadge';
import { PageHeader } from '../components/layout/PageHeader';
import { useApp } from '../context/AppContext';
import { useData } from '../hooks/useData';
import { loadIntegrations, saveIntegrationConfig, testConnection, queryIntegration } from '../services/integrationsService';
import type { Integration, IntegrationField } from '../types/integration';
import { formatDateTime } from '../utils/formatDate';
import { isBackendConfigured } from '../services/apiClient';
import { HostCollectors } from '../components/integrations/HostCollectors';

const icons: Record<string, LucideIcon> = {
  activepieces: Workflow, wazuh: Shield, sysmon: Radar, suricata: Network, zeek: Network,
  virustotal: ScanSearch, abuseipdb: Shield, urlscan: Globe, clamav: Bug, yara: ScanSearch,
};
const initialQuery = (fields: IntegrationField[] = []) => Object.fromEntries(fields.map(f => [f.key, f.key === 'limit' ? '25' : f.key === 'resource' ? 'agents' : f.key === 'type' ? 'ip' : '']));
const FieldControl = ({ field, value, onChange, disabled = false }: { field: IntegrationField; value: string; onChange: (v: string) => void; disabled?: boolean }) => {
  if (field.key === 'type') return <select className="input mono" value={value || 'ip'} onChange={e => onChange(e.target.value)}><option value="ip">IP address</option><option value="domain">Domain</option><option value="url">URL</option><option value="hash">File hash</option></select>;
  if (field.key === 'resource') return <select className="input mono" value={value || 'agents'} onChange={e => onChange(e.target.value)}><option value="agents">List agents</option><option value="agent">Get one agent</option><option value="manager">Manager info</option><option value="alerts">Recent Wazuh alerts</option></select>;
  return <input className="input mono" type={field.type === 'password' || field.secret ? 'password' : field.type === 'url' ? 'url' : 'text'} value={value ?? ''} placeholder={field.placeholder} onChange={e => onChange(e.target.value)} autoComplete="off" disabled={disabled} />;
};

export default function Integrations() {
  const { data, loading, error, reload } = useData(loadIntegrations);
  const { toast } = useApp();
  const [editing, setEditing] = useState<Integration | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [testing, setTesting] = useState<string | null>(null);
  const [querying, setQuerying] = useState<string | null>(null);
  const [queryValues, setQueryValues] = useState<Record<string, Record<string, string>>>({});
  const [queryResults, setQueryResults] = useState<Record<string, string>>({});
  const [expandedQuery, setExpandedQuery] = useState<string | null>(null);

  const configure = (i: Integration) => { setEditing(i); setValues({}); };
  const save = async () => {
    if (!editing) return;
    try {
      await saveIntegrationConfig(editing, values);
      toast(`${editing.name}: credentials/configuration encrypted and saved for your user account. Run Test Connection to verify the live service.`, 'success');
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

  return (
    <>
      <PageHeader title="Connect your tools" subtitle="A dynamic connector registry — each user connects their own security tools and API keys." />
      <HostCollectors />
      <div className="mb-4 rounded-lg border border-sx-gold/25 bg-sx-gold/5 p-3 text-xs text-sx-gold/90">
        {isBackendConfigured
          ? 'Credentials are encrypted at rest and scoped to your signed-in user and organization. A saved key is not a verified connection; use Test Connection.'
          : 'Connectors require the SentinelX backend. Demo mode never stores API keys or secrets.'}
      </div>
      <div className="mb-4 grid gap-3 md:grid-cols-3">
        <div className="panel p-3"><div className="text-[10px] uppercase tracking-wider text-sx-mute">Adapter contract</div><div className="mt-1 text-sm font-semibold">connect · test · query · schema</div><div className="mt-1 text-[11px] text-sx-mute">Versioned registry, same contract for every provider.</div></div>
        <div className="panel p-3"><div className="text-[10px] uppercase tracking-wider text-sx-mute">Credential ownership</div><div className="mt-1 text-sm font-semibold">Per-user encrypted secrets</div><div className="mt-1 text-[11px] text-sx-mute">One user's keys are never returned to another user.</div></div>
        <div className="panel p-3"><div className="text-[10px] uppercase tracking-wider text-sx-mute">Connection state</div><div className="mt-1 text-sm font-semibold">Saved ≠ verified</div><div className="mt-1 text-[11px] text-sx-mute">Health only turns green after a real provider/collector check.</div></div>
      </div>
      {loading ? <div className="panel"><LoadingState /></div> : error ? <div className="panel"><ErrorState message={error} onRetry={reload} /></div> : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {(data ?? []).map(i => {
            const Icon = icons[i.id] ?? Shield;
            const querySchema = i.schema?.query;
            return (
              <Panel key={i.id} bodyClass="flex h-full flex-col p-4" className="flex flex-col">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-sx-gold/30 bg-sx-gold/5"><Icon className="h-5 w-5 text-sx-gold" aria-hidden /></div>
                    <div><div className="text-sm font-semibold">{i.name}</div><div className="text-[11px] text-sx-mute">{i.category}</div></div>
                  </div>
                  <StatusBadge value={i.state} />
                </div>
                <p className="mt-3 flex-1 text-xs text-sx-mute">{i.purpose}</p>
                <dl className="mt-3 space-y-1.5 border-t border-sx-line pt-3 text-[11px]">
                  <div className="flex justify-between"><dt className="text-sx-mute">Credentials</dt><dd>{i.configured ? <span className="text-sx-warn">Saved · not verified</span> : <span className="text-sx-mute">Not connected</span>}</dd></div>
                  <div className="flex justify-between"><dt className="text-sx-mute">Live test</dt><dd className={i.verified ? 'text-sx-green' : 'text-sx-mute'}>{i.verified ? 'Passed' : 'Not verified'}</dd></div>
                  <div className="flex justify-between"><dt className="text-sx-mute">Last health check</dt><dd className="mono">{i.lastHealthCheck ? formatDateTime(i.lastHealthCheck) : 'never'}</dd></div>
                  {i.configuredKeys?.length ? <div className="text-[10px] text-sx-mute">Saved fields: {i.configuredKeys.join(', ')}</div> : null}
                </dl>
                <div className="mt-3 flex flex-wrap gap-2">
                  {i.fields.length > 0 ? <button className="btn flex-1" onClick={() => configure(i)} disabled={!isBackendConfigured}><Settings2 className="h-3.5 w-3.5" /> Connect / update</button> : <div className="flex flex-1 items-center justify-center rounded border border-sx-line px-2 text-[10px] text-sx-mute">Gateway managed</div>}
                  <button className="btn btn-gold flex-1" onClick={() => test(i)} disabled={!isBackendConfigured || testing === i.id || (!i.configured && i.id !== 'activepieces' && !['sysmon','suricata','zeek'].includes(i.id))}><TestTube2 className="h-3.5 w-3.5" /> {testing === i.id ? 'Testing…' : 'Test connection'}</button>
                  {querySchema?.supported && <button className="btn w-full" onClick={() => { setExpandedQuery(expandedQuery === i.id ? null : i.id); setQueryValues(prev => ({ ...prev, [i.id]: prev[i.id] ?? initialQuery(querySchema.fields) })); }}><Search className="h-3.5 w-3.5" /> Query tool</button>}
                </div>
                {expandedQuery === i.id && querySchema?.supported && (
                  <div className="mt-3 space-y-2 border-t border-sx-line pt-3">
                    <div className="text-xs font-semibold">Query {i.name}</div>
                    <p className="text-[10px] text-sx-mute">{querySchema.description}</p>
                    {(querySchema.fields ?? []).map(f => (
                      <Field key={f.key} label={f.label} htmlFor={`q-${i.id}-${f.key}`}>
                        <FieldControl field={f} value={queryValues[i.id]?.[f.key] ?? ''} onChange={v => setQueryField(i.id,f.key,v)} />
                      </Field>
                    ))}
                    <button className="btn btn-gold w-full" onClick={() => runQuery(i)} disabled={querying === i.id || (!i.configured && !i.verified)}>{querying === i.id ? 'Querying…' : 'Run read-only query'}</button>
                    {queryResults[i.id] && <pre className="max-h-64 overflow-auto rounded border border-sx-line bg-sx-bg p-2 text-[10px] text-sx-text whitespace-pre-wrap break-all">{queryResults[i.id]}</pre>}
                    {i.id === 'virustotal' && <p className="text-[10px] text-sx-warn">Privacy: VirusTotal notes that queried indicators can be added to its shared dataset. Do not submit confidential or personal indicators. Check its terms before using the Community API in a product.</p>}
                  </div>
                )}
              </Panel>
            );
          })}
        </div>
      )}
      <Modal open={!!editing} onClose={() => setEditing(null)} title={`Connect ${editing?.name ?? ''}`}>
        {editing && (
          <div className="space-y-3">
            <p className="text-[11px] text-sx-mute">These credentials belong to your signed-in account. They are encrypted by the SentinelX backend and are never sent back to the browser.</p>
            {editing.fields.map(f => (
              <Field key={f.key} label={f.label} htmlFor={`f-${f.key}`}>
                <FieldControl field={f} value={values[f.key] ?? ''} onChange={v => setValues(prev => ({ ...prev, [f.key]: v }))} disabled={!isBackendConfigured} />
                {f.required && <p className="mt-1 text-[10px] text-sx-mute">Required</p>}
                {f.help && <p className="mt-1 text-[10px] text-sx-mute">{f.help}</p>}
              </Field>
            ))}
            <div className="rounded border border-sx-line bg-sx-bg p-2 text-[10px] text-sx-mute">Wazuh security: keep API 55000 private. Use a trusted HTTPS Cloudflare Tunnel with Access service credentials or a private bridge; never expose the Manager API publicly.</div>
            <div className="flex justify-end gap-2"><button className="btn" onClick={() => setEditing(null)}>Cancel</button><button className="btn btn-primary" onClick={save} disabled={!isBackendConfigured}>{'Save encrypted credentials'}</button></div>
          </div>
        )}
      </Modal>
    </>
  );
}
