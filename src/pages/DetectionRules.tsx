import { Plus } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Drawer } from '../components/common/Drawer';
import { Field, Panel, Select, SortHeader } from '../components/common/Controls';
import { EmptyState } from '../components/common/EmptyState';
import { Modal } from '../components/common/Modal';
import { SearchInput } from '../components/common/SearchInput';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { PageHeader } from '../components/layout/PageHeader';
import { useApp } from '../context/AppContext';
import { useLocalStore } from '../hooks/useLocalStore';
import { useData } from '../hooks/useData';
import { isBackendConfigured } from '../services/apiClient';
import { addRule, rulesStore, loadRules } from '../services/miscService';
import type { Severity } from '../types/alert';
import type { DetectionRule } from '../types/extra';
import { timeAgo } from '../utils/formatDate';
import { severityRank } from '../utils/severity';

type SortKey = 'name' | 'id' | 'severity' | 'status' | 'lastTested';
const blank = { name: '', description: '', severity: 'medium' as Severity, requiredEvidence: '', logic: '', response: '' };

export default function DetectionRules() {
  const localRules = useLocalStore(rulesStore);
  const remoteRules = useData(loadRules);
  const rules = isBackendConfigured ? remoteRules.data ?? [] : localRules;
  const { toast } = useApp();
  const [q, setQ] = useState('');
  const [sev, setSev] = useState('all');
  const [st, setSt] = useState('all');
  const [sort, setSort] = useState<{ k: SortKey; d: 'asc' | 'desc' }>({ k: 'id', d: 'asc' });
  const [sel, setSel] = useState<DetectionRule | null>(null);
  const [editor, setEditor] = useState(false);
  const [form, setForm] = useState(blank);

  const list = useMemo(() => {
    const s = q.trim().toLowerCase();
    const dir = sort.d === 'asc' ? 1 : -1;
    return rules
      .filter((r) => (sev === 'all' || r.severity === sev) && (st === 'all' || r.status === st) && (!s || [r.name, r.id, r.category, r.source, ...r.mitre].some((v) => v.toLowerCase().includes(s))))
      .sort((a, b) => {
        if (sort.k === 'severity') return (severityRank[a.severity] - severityRank[b.severity]) * dir;
        if (sort.k === 'lastTested') return ((a.lastTested ? +new Date(a.lastTested) : 0) - (b.lastTested ? +new Date(b.lastTested) : 0)) * dir;
        return String(a[sort.k]).localeCompare(String(b[sort.k])) * dir;
      });
  }, [rules, q, sev, st, sort]);

  const onSort = (k: SortKey) => setSort((s) => (s.k === k ? { k, d: s.d === 'asc' ? 'desc' : 'asc' } : { k, d: 'asc' }));
  const H = (k: SortKey, label: string) => <SortHeader label={label} active={sort.k === k} dir={sort.d} onClick={() => onSort(k)} />;
  const lines = (s: string) => s.split('\n').map((x) => x.trim()).filter(Boolean);

  const save = () => {
    if (!form.name.trim()) return;
    const r = addRule({ name: form.name.trim(), description: form.description.trim(), category: 'Custom', severity: form.severity, source: 'Not assigned', requiredEvidence: lines(form.requiredEvidence), logic: form.logic.trim(), response: lines(form.response) });
    setEditor(false); setForm(blank);
    toast(`${r.id} saved as a draft. It is not deployed or executed — backend validation is required.`, 'info');
  };

  return (
    <>
      <PageHeader title="Detection Rules" subtitle="Manage detection logic and validation status."
        actions={!isBackendConfigured ? <button className="btn btn-primary" onClick={() => setEditor(true)}><Plus className="h-3.5 w-3.5" /> New rule</button> : undefined} />

      {isBackendConfigured && (remoteRules.loading ? <div className="mb-3 text-xs text-sx-mute">Loading detection rules from SentinelX backend…</div> : remoteRules.error ? <div className="mb-3 text-xs text-sx-red">Backend rules unavailable: {remoteRules.error}</div> : <div className="mb-3 text-xs text-sx-mute">Read-only rules from the SentinelX backend. Rule editing and deployment are disabled until write APIs are complete.</div>)}
      <Panel>
        <div className="flex flex-wrap items-center gap-2 border-b border-sx-line p-3">
          <SearchInput className="w-full sm:w-72" value={q} onChange={setQ} placeholder="Search name, ID, category, MITRE" label="Search rules" />
          <Select label="Severity" className="w-36" value={sev} onChange={setSev} options={[{ value: 'all', label: 'All severities' }, ...['critical', 'high', 'medium', 'low'].map((v) => ({ value: v, label: v[0].toUpperCase() + v.slice(1) }))]} />
          <Select label="Rule status" className="w-36" value={st} onChange={setSt} options={[{ value: 'all', label: 'All statuses' }, { value: 'enabled', label: 'Enabled' }, { value: 'disabled', label: 'Disabled' }, { value: 'draft', label: 'Draft' }]} />
        </div>
        {list.length === 0 ? <EmptyState title="No rules match" description={isBackendConfigured ? "No backend detection rules match the current filters." : "Adjust filters or create a new rule."} /> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[980px] text-xs">
              <thead className="border-b border-sx-line bg-sx-bg/40"><tr>
                {H('name', 'Rule name')}{H('id', 'Rule ID')}<th className="th">Category</th>{H('severity', 'Severity')}<th className="th">Source</th><th className="th">MITRE</th>{H('status', 'Status')}{H('lastTested', 'Last tested')}<th className="th">Validation</th>
              </tr></thead>
              <tbody className="divide-y divide-sx-line">
                {list.map((r) => (
                  <tr key={r.id} className="row-hover" tabIndex={0} onClick={() => setSel(r)} onKeyDown={(e) => e.key === 'Enter' && setSel(r)}>
                    <td className="td font-medium">{r.name}</td>
                    <td className="td mono text-sx-gold">{r.id}</td>
                    <td className="td text-sx-mute">{r.category}</td>
                    <td className="td"><SeverityBadge severity={r.severity} /></td>
                    <td className="td text-sx-mute">{r.source}</td>
                    <td className="td mono text-sx-mute">{r.mitre.join(', ') || '—'}</td>
                    <td className="td"><StatusBadge value={r.status} /></td>
                    <td className="td whitespace-nowrap text-sx-mute">{r.lastTested ? timeAgo(r.lastTested) : 'never'}</td>
                    <td className="td"><StatusBadge value={r.maturity} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Drawer open={!!sel} onClose={() => setSel(null)} title={sel?.name} subtitle={<span className="mono">{sel?.id} · {sel?.category}</span>}
        footer={isBackendConfigured ? <span className="text-[11px] text-sx-mute">Backend rule record · write and deployment APIs pending.</span> : <><button className="btn" onClick={() => toast('Backend required: rule validation and deployment run server-side.', 'warn')}>Validate</button><button className="btn btn-gold" onClick={() => toast('Backend required: deployment to Wazuh/ActivePieces is not available in the prototype.', 'warn')}>Deploy</button></>}>
        {sel && (
          <div className="space-y-4 text-xs">
            <div className="flex flex-wrap gap-2"><SeverityBadge severity={sel.severity} /><StatusBadge value={sel.status} /><StatusBadge value={sel.maturity} /></div>
            <p className="text-[13px]">{sel.description}</p>
            <div><h3 className="label">Detection logic (descriptive — never executed in the browser)</h3><pre className="mono overflow-auto rounded-lg border border-sx-line bg-sx-bg p-3 text-[11px]">{sel.logic}</pre></div>
            <div><h3 className="label">Required evidence</h3><ul className="list-disc space-y-1 pl-4 marker:text-sx-gold">{sel.requiredEvidence.map((e) => <li key={e}>{e}</li>)}</ul></div>
            <div><h3 className="label">MITRE ATT&CK</h3>{sel.mitre.length ? <div className="flex gap-2">{sel.mitre.map((m) => <span key={m} className="mono rounded border border-sx-gold/30 bg-sx-gold/5 px-1.5 py-0.5 text-sx-gold">{m}</span>)}</div> : <span className="text-sx-mute">None</span>}</div>
            <div><h3 className="label">Response recommendations</h3><ul className="list-disc space-y-1 pl-4 marker:text-sx-gold">{sel.response.map((e) => <li key={e}>{e}</li>)}</ul></div>
            <div className="grid grid-cols-2 gap-3 rounded-lg border border-sx-line bg-sx-panel p-3"><div><div className="text-sx-mute">Source</div>{sel.source}</div><div><div className="text-sx-mute">Last tested</div>{sel.lastTested ? timeAgo(sel.lastTested) : 'never'}</div></div>
          </div>
        )}
      </Drawer>

      <Modal open={editor} onClose={() => setEditor(false)} title="Rule editor" size="lg">
        <div className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-[1fr_180px]">
            <Field label="Rule name" htmlFor="r-name"><input id="r-name" className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
            <Field label="Severity"><Select label="Severity" value={form.severity} onChange={(v) => setForm({ ...form, severity: v as Severity })} options={['critical', 'high', 'medium', 'low'].map((v) => ({ value: v, label: v[0].toUpperCase() + v.slice(1) }))} /></Field>
          </div>
          <Field label="Description" htmlFor="r-desc"><textarea id="r-desc" className="input min-h-[56px]" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Required evidence (one per line)" htmlFor="r-ev"><textarea id="r-ev" className="input min-h-[90px]" value={form.requiredEvidence} onChange={(e) => setForm({ ...form, requiredEvidence: e.target.value })} /></Field>
            <Field label="Response recommendations (one per line)" htmlFor="r-rs"><textarea id="r-rs" className="input min-h-[90px]" value={form.response} onChange={(e) => setForm({ ...form, response: e.target.value })} /></Field>
          </div>
          <Field label="Detection logic (descriptive)" htmlFor="r-lg"><textarea id="r-lg" className="input mono min-h-[90px]" value={form.logic} onChange={(e) => setForm({ ...form, logic: e.target.value })} placeholder="count(EventID=4625) by IpAddress >= 10 within 10m" /></Field>
          <p className="rounded-lg border border-sx-line bg-sx-elev/40 p-2.5 text-[11px] text-sx-mute">Logic is stored as text only. The browser never executes it. Validation and deployment must be done by the backend or the target security tool.</p>
          <div className="flex justify-end gap-2"><button className="btn" onClick={() => setEditor(false)}>Cancel</button><button className="btn btn-primary" disabled={!form.name.trim()} onClick={save}>Save draft</button></div>
        </div>
      </Modal>
    </>
  );
}
