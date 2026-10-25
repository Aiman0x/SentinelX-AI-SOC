import { Plus } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { CaseDetails } from '../components/cases/CaseDetails';
import { CaseTable } from '../components/cases/CaseTable';
import { Field, Panel, Segmented, Select } from '../components/common/Controls';
import { EmptyState } from '../components/common/EmptyState';
import { Modal } from '../components/common/Modal';
import { SearchInput } from '../components/common/SearchInput';
import { PageHeader } from '../components/layout/PageHeader';
import { useApp } from '../context/AppContext';
import { useAlerts } from '../hooks/useAlerts';
import { useCases } from '../hooks/useCases';
import { ANALYSTS, createCase } from '../services/casesService';
import type { Severity } from '../types/alert';

type Filter = 'all' | 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';

export default function Cases() {
  const cases = useCases();
  const { alerts } = useAlerts();
  const { toast, analyst } = useApp();
  const [params, setParams] = useSearchParams();
  const [filter, setFilter] = useState<Filter>('all');
  const [q, setQ] = useState('');
  const [selected, setSelected] = useState<string | null>(params.get('case'));
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ title: '', severity: 'medium' as Severity, assignee: analyst, asset: '', overview: '' });

  useEffect(() => {
    const c = params.get('case');
    if (c) { setSelected(c); params.delete('case'); setParams(params, { replace: true }); }
  }, [params, setParams]);

  const list = useMemo(() => {
    const s = q.trim().toLowerCase();
    return cases.filter((c) => (filter === 'all' || c.status === filter) && (!s || [c.id, c.title, c.assignee, ...c.assets].some((v) => v.toLowerCase().includes(s))));
  }, [cases, filter, q]);

  const current = cases.find((c) => c.id === selected);

  const submit = () => {
    if (!form.title.trim()) return;
    const c = createCase({ title: form.title.trim(), severity: form.severity, assignee: form.assignee, assets: form.asset.split(',').map((x) => x.trim()).filter(Boolean), overview: form.overview.trim() || 'No overview provided.' });
    setCreating(false);
    setForm({ title: '', severity: 'medium', assignee: analyst, asset: '', overview: '' });
    setSelected(c.id);
    toast(`Demo case ${c.id} created.`, 'success');
  };

  return (
    <>
      <PageHeader title="Incidents & Cases" subtitle="Track investigations from detection to closure."
        actions={<button className="btn btn-primary" onClick={() => setCreating(true)}><Plus className="h-3.5 w-3.5" /> New demo case</button>} />

      <Panel>
        <div className="flex flex-wrap items-center gap-3 border-b border-sx-line p-3">
          <Segmented<Filter> label="Filter by status" value={filter} onChange={setFilter}
            options={(['all', 'open', 'investigating', 'contained', 'resolved', 'closed'] as Filter[]).map((v) => ({ value: v, label: v[0].toUpperCase() + v.slice(1) }))} />
          <SearchInput className="w-full sm:ml-auto sm:w-64" value={q} onChange={setQ} placeholder="Search cases" label="Search cases" />
        </div>
        {list.length === 0 ? <EmptyState title="No cases found" description="Change the filter or create a new demo case." /> : <CaseTable cases={list} selectedId={selected} onSelect={setSelected} />}
      </Panel>

      {current && <div className="mt-4"><CaseDetails c={current} alerts={alerts} onClose={() => setSelected(null)} /></div>}

      <Modal open={creating} onClose={() => setCreating(false)} title="New demo case">
        <div className="space-y-3">
          <Field label="Title" htmlFor="case-title"><input id="case-title" className="input" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} placeholder="e.g. Suspicious login on SRV-APP-03" /></Field>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Severity"><Select label="Severity" value={form.severity} onChange={(v) => setForm({ ...form, severity: v as Severity })} options={['critical', 'high', 'medium', 'low'].map((v) => ({ value: v, label: v[0].toUpperCase() + v.slice(1) }))} /></Field>
            <Field label="Assigned analyst"><Select label="Assigned analyst" value={form.assignee} onChange={(v) => setForm({ ...form, assignee: v })} options={ANALYSTS.map((v) => ({ value: v, label: v }))} /></Field>
          </div>
          <Field label="Related assets (comma separated)" htmlFor="case-assets"><input id="case-assets" className="input mono" value={form.asset} onChange={(e) => setForm({ ...form, asset: e.target.value })} placeholder="WS-FIN-014, SRV-DC-01" /></Field>
          <Field label="Overview" htmlFor="case-ov"><textarea id="case-ov" className="input min-h-[72px]" value={form.overview} onChange={(e) => setForm({ ...form, overview: e.target.value })} /></Field>
          <div className="flex justify-end gap-2"><button className="btn" onClick={() => setCreating(false)}>Cancel</button><button className="btn btn-primary" disabled={!form.title.trim()} onClick={submit}>Create case</button></div>
        </div>
      </Modal>
    </>
  );
}
