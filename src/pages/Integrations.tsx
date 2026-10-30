import { Bug, KeyRound, Network, Radar, ScanSearch, Settings2, Shield, TestTube2, Workflow, type LucideIcon } from 'lucide-react';
import { useState } from 'react';
import { Field, Panel } from '../components/common/Controls';
import { ErrorState, LoadingState } from '../components/common/EmptyState';
import { Modal } from '../components/common/Modal';
import { StatusBadge } from '../components/common/StatusBadge';
import { PageHeader } from '../components/layout/PageHeader';
import { useApp } from '../context/AppContext';
import { useData } from '../hooks/useData';
import { useLocalStore } from '../hooks/useLocalStore';
import { integrationConfigStore, loadIntegrations, saveIntegrationConfig, testConnection } from '../services/integrationsService';
import type { Integration } from '../types/integration';
import { formatDateTime } from '../utils/formatDate';
import { isBackendConfigured } from '../services/apiClient';

const icons: Record<string, LucideIcon> = { activepieces: Workflow, wazuh: Shield, sysmon: Radar, clamav: Bug, yara: ScanSearch, suricata: Network, zeek: Network };

export default function Integrations() {
  const { data, loading, error, reload } = useData(loadIntegrations);
  const saved = useLocalStore(integrationConfigStore);
  const { toast } = useApp();
  const [editing, setEditing] = useState<Integration | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [testing, setTesting] = useState<string | null>(null);

  const configure = (i: Integration) => { setEditing(i); setValues(i.savedConfig ?? saved[i.id]?.values ?? {}); };
  const save = async () => {
    if (!editing) return;
    try {
      await saveIntegrationConfig(editing, values);
      toast(`${editing.name}: configuration saved securely. Connection is NOT verified.`, 'info');
      setEditing(null);
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Configuration could not be saved.', 'warn');
    }
  };
  const test = async (i: Integration) => {
    setTesting(i.id);
    const r = await testConnection(i);
    setTesting(null);
    toast(`${i.name}: ${r.message}`, r.ok ? 'success' : 'warn');
  };

  return (
    <>
      <PageHeader title="Integrations" subtitle="Planned and optional defensive tool connections." />
      <div className="mb-4 rounded-lg border border-sx-gold/25 bg-sx-gold/5 p-3 text-xs text-sx-gold/90">
        These tools are <strong>planned or optional</strong> — none is assumed to be installed. States shown are sample values. “Connected” appears only after a real backend health check passes. Saving a configuration is not the same as a verified connection.
      </div>

      {loading ? <div className="panel"><LoadingState /></div> : error ? <div className="panel"><ErrorState message={error} onRetry={reload} /></div> : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {(data ?? []).map((i) => {
            const Icon = icons[i.id] ?? Shield;
            const s = saved[i.id];
            const configured = i.configured || !!s?.savedAt;
            const last = s?.lastTest;
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
                  <div className="flex justify-between"><dt className="text-sx-mute">Configuration</dt><dd>{configured ? <span className="text-sx-warn">Saved · not verified</span> : <span className="text-sx-mute">Not configured</span>}</dd></div>
                  <div className="flex justify-between"><dt className="text-sx-mute">Verified connection</dt><dd className="text-sx-mute">No</dd></div>
                  <div className="flex justify-between"><dt className="text-sx-mute">Last successful health check</dt><dd className="mono">{i.lastHealthCheck ? formatDateTime(i.lastHealthCheck) : 'never'}</dd></div>
                  {last && <div className="rounded border border-sx-line bg-sx-bg p-2 text-sx-mute"><span className="text-sx-warn">Last test:</span> {last.message}</div>}
                </dl>
                <div className="mt-3 flex gap-2">
                  <button className="btn flex-1" onClick={() => configure(i)}><Settings2 className="h-3.5 w-3.5" /> Configure</button>
                  {!isBackendConfigured ? <button className="btn btn-gold flex-1" onClick={() => test(i)} disabled={testing === i.id}><TestTube2 className="h-3.5 w-3.5" /> {testing === i.id ? 'Testing…' : 'Test Connection'}</button> : <div className="flex flex-1 items-center justify-center rounded border border-sx-line px-2 text-[10px] text-sx-mute">Adapter test pending</div>}
                </div>
              </Panel>
            );
          })}
        </div>
      )}

      <Modal open={!!editing} onClose={() => setEditing(null)} title={`Configure ${editing?.name ?? ''}`}>
        {editing && (
          <div className="space-y-3">
            {editing.fields.map((f) => (
              <Field key={f.key} label={f.label} htmlFor={`f-${f.key}`}>
                <input id={`f-${f.key}`} type={f.secret ? 'password' : 'text'} className="input mono" value={values[f.key] ?? ''} placeholder={f.secret ? 'Enter secret (stored encrypted on backend)' : f.placeholder} onChange={(e) => setValues({ ...values, [f.key]: e.target.value })} autoComplete="off" />
                {f.secret && <p className="mt-1 text-[10px] text-sx-mute">Sent only over HTTPS to SentinelX and encrypted before storage. Secret values are never returned to the browser.</p>}
                {f.help && <p className="mt-1 text-[10px] text-sx-mute">{f.help}</p>}
              </Field>
            ))}
            <p className="text-[11px] text-sx-mute">{isBackendConfigured ? 'Saving sends configuration to the authenticated backend, where it is encrypted at rest. It does not connect to or test the tool.' : 'Demo mode stores only non-secret values in this browser. Configure secrets only after the backend is connected.'}</p>
            <div className="flex justify-end gap-2"><button className="btn" onClick={() => setEditing(null)}>Cancel</button><button className="btn btn-primary" onClick={save}>Save configuration</button></div>
          </div>
        )}
      </Modal>
    </>
  );
}
