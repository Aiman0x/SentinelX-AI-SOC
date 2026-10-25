import { Info, Plus } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Field, Panel, Select } from '../components/common/Controls';
import { EmptyState } from '../components/common/EmptyState';
import { Modal } from '../components/common/Modal';
import { SearchInput } from '../components/common/SearchInput';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { PageHeader } from '../components/layout/PageHeader';
import { useApp } from '../context/AppContext';
import { useLocalStore } from '../hooks/useLocalStore';
import { addAsset, assetsStore } from '../services/miscService';
import type { AssetType, Criticality } from '../types/asset';
import { timeAgo } from '../utils/formatDate';

const TYPES: AssetType[] = ['Server', 'Workstation', 'Domain', 'Network device', 'Cloud service', 'Database'];
const METHODS = ['None (registered only)', 'Wazuh agent', 'Sysmon', 'Syslog', 'Suricata / Zeek sensor', 'API / cloud connector'];
const blank = { name: '', type: 'Server' as AssetType, host: '', ip: '', os: '', criticality: 'medium' as Criticality, method: METHODS[0] };

export default function Assets() {
  const assets = useLocalStore(assetsStore);
  const { toast } = useApp();
  const [q, setQ] = useState('');
  const [f, setF] = useState({ type: 'all', os: 'all', crit: 'all', mon: 'all' });
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState(blank);

  const oses = useMemo(() => [...new Set(assets.map((a) => a.os).filter((o) => o !== '—'))].sort(), [assets]);
  const list = assets.filter((a) => {
    const s = q.trim().toLowerCase();
    return (f.type === 'all' || a.type === f.type) && (f.os === 'all' || a.os === f.os) && (f.crit === 'all' || a.criticality === f.crit) && (f.mon === 'all' || a.monitoring === f.mon)
      && (!s || [a.name, a.host, a.ip, a.id].some((v) => v.toLowerCase().includes(s)));
  });

  const submit = () => {
    if (!form.name.trim() || !form.host.trim()) return;
    const a = addAsset({ name: form.name.trim(), host: form.host.trim(), ip: form.ip.trim() || '—', os: form.os.trim() || '—', type: form.type, criticality: form.criticality, method: form.method });
    setOpen(false); setForm(blank);
    toast(`${a.id} registered. No scan or connection was made — telemetry is unverified.`, 'success');
  };

  return (
    <>
      <PageHeader title="Assets & Endpoints" subtitle="Inventory of systems registered for defensive monitoring."
        actions={<button className="btn btn-primary" onClick={() => setOpen(true)}><Plus className="h-3.5 w-3.5" /> Add Asset</button>} />

      <div className="mb-4 flex items-start gap-2 rounded-lg border border-sx-gold/25 bg-sx-gold/5 p-3 text-xs text-sx-gold/90">
        <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        <span><strong>Registered</strong> means the asset exists in the SentinelX inventory only. <strong>Verified</strong> means telemetry was actually received through an authorised, configured integration. SentinelX never scans or accesses a target you add.</span>
      </div>

      <Panel>
        <div className="flex flex-wrap items-center gap-2 border-b border-sx-line p-3">
          <SearchInput className="w-full sm:w-64" value={q} onChange={setQ} placeholder="Search name, host, IP" label="Search assets" />
          <Select label="Asset type" className="w-40" value={f.type} onChange={(v) => setF({ ...f, type: v })} options={[{ value: 'all', label: 'All types' }, ...TYPES.map((t) => ({ value: t, label: t }))]} />
          <Select label="Operating system" className="w-44" value={f.os} onChange={(v) => setF({ ...f, os: v })} options={[{ value: 'all', label: 'All OS' }, ...oses.map((t) => ({ value: t, label: t }))]} />
          <Select label="Criticality" className="w-36" value={f.crit} onChange={(v) => setF({ ...f, crit: v })} options={[{ value: 'all', label: 'All criticality' }, ...['critical', 'high', 'medium', 'low'].map((t) => ({ value: t, label: t[0].toUpperCase() + t.slice(1) }))]} />
          <Select label="Monitoring status" className="w-40" value={f.mon} onChange={(v) => setF({ ...f, mon: v })} options={[{ value: 'all', label: 'All monitoring' }, { value: 'verified', label: 'Verified' }, { value: 'registered', label: 'Registered' }, { value: 'stale', label: 'Stale' }, { value: 'unmonitored', label: 'Unmonitored' }]} />
        </div>
        {list.length === 0 ? <EmptyState title="No assets match" description="Adjust filters or add an asset." /> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-xs">
              <thead className="border-b border-sx-line bg-sx-bg/40"><tr>{['Asset', 'Hostname / domain', 'IP', 'Operating system', 'Type', 'Criticality', 'Monitoring', 'Method', 'Last event'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
              <tbody className="divide-y divide-sx-line">
                {list.map((a) => (
                  <tr key={a.id} className="transition-colors hover:bg-sx-elev/50">
                    <td className="td"><div className="font-medium">{a.name}</div><div className="mono text-[10px] text-sx-mute">{a.id}{a.addedBy === 'user' && ' · added by you'}</div></td>
                    <td className="td mono">{a.host}</td>
                    <td className="td mono text-sx-mute">{a.ip}</td>
                    <td className="td text-sx-mute">{a.os}</td>
                    <td className="td">{a.type}</td>
                    <td className="td"><SeverityBadge severity={a.criticality} /></td>
                    <td className="td"><StatusBadge value={a.monitoring} /></td>
                    <td className="td text-sx-mute">{a.method}</td>
                    <td className="td whitespace-nowrap text-sx-mute">{a.lastEvent ? timeAgo(a.lastEvent) : 'never'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Modal open={open} onClose={() => setOpen(false)} title="Add Asset">
        <div className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Asset name" htmlFor="a-name"><input id="a-name" className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g. Payroll Server" /></Field>
            <Field label="Asset type"><Select label="Asset type" value={form.type} onChange={(v) => setForm({ ...form, type: v as AssetType })} options={TYPES.map((t) => ({ value: t, label: t }))} /></Field>
            <Field label="Hostname or domain" htmlFor="a-host"><input id="a-host" className="input mono" value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="SRV-PAY-01 or pay.example.com" /></Field>
            <Field label="IP address (if applicable)" htmlFor="a-ip"><input id="a-ip" className="input mono" value={form.ip} onChange={(e) => setForm({ ...form, ip: e.target.value })} placeholder="10.0.0.10" /></Field>
            <Field label="Operating system" htmlFor="a-os"><input id="a-os" className="input" value={form.os} onChange={(e) => setForm({ ...form, os: e.target.value })} placeholder="Windows Server 2022" /></Field>
            <Field label="Business criticality"><Select label="Business criticality" value={form.criticality} onChange={(v) => setForm({ ...form, criticality: v as Criticality })} options={['critical', 'high', 'medium', 'low'].map((t) => ({ value: t, label: t[0].toUpperCase() + t.slice(1) }))} /></Field>
          </div>
          <Field label="Monitoring method"><Select label="Monitoring method" value={form.method} onChange={(v) => setForm({ ...form, method: v })} options={METHODS.map((t) => ({ value: t, label: t }))} /></Field>
          <p className="rounded-lg border border-sx-line bg-sx-elev/40 p-2.5 text-[11px] text-sx-mute">Adding an asset only <strong className="text-sx-ink">registers</strong> it. SentinelX will not scan, probe or log in to it. Monitoring requires an authorised, configured integration, after which telemetry must be verified.</p>
          <div className="flex justify-end gap-2"><button className="btn" onClick={() => setOpen(false)}>Cancel</button><button className="btn btn-primary" disabled={!form.name.trim() || !form.host.trim()} onClick={submit}>Register asset</button></div>
        </div>
      </Modal>
    </>
  );
}
