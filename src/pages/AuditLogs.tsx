import { useMemo, useState } from 'react';
import { Panel, Select } from '../components/common/Controls';
import { EmptyState, ErrorState, LoadingState } from '../components/common/EmptyState';
import { SearchInput } from '../components/common/SearchInput';
import { StatusBadge } from '../components/common/StatusBadge';
import { PageHeader } from '../components/layout/PageHeader';
import { useData } from '../hooks/useData';
import { loadAudit } from '../services/miscService';
import { formatDateTime } from '../utils/formatDate';
import { cap } from '../utils/severity';
import { isBackendConfigured } from '../services/apiClient';

export default function AuditLogs() {
  const { data, loading, error, reload } = useData(loadAudit);
  const [q, setQ] = useState('');
  const [user, setUser] = useState('all');
  const [type, setType] = useState('all');
  const [result, setResult] = useState('all');
  const [date, setDate] = useState('all');

  const users = useMemo(() => [...new Set((data ?? []).map((r) => r.actor))].sort(), [data]);
  const types = useMemo(() => [...new Set((data ?? []).map((r) => r.actionType))].sort(), [data]);
  const list = (data ?? []).filter((r) => {
    const s = q.trim().toLowerCase();
    const cutoff = date === 'all' ? 0 : Date.now() - Number(date) * 3600000;
    return (user === 'all' || r.actor === user) && (type === 'all' || r.actionType === type) && (result === 'all' || r.result === result) && +new Date(r.time) >= cutoff
      && (!s || [r.action, r.target, r.actor, r.source, r.id].some((v) => v.toLowerCase().includes(s)));
  });

  return (
    <>
      <PageHeader title="Audit Logs" subtitle="Searchable trail of analyst and service actions." />
      <div className="mb-4 rounded-lg border border-sx-gold/25 bg-sx-gold/5 p-3 text-xs text-sx-gold/90">{isBackendConfigured ? 'Audit records loaded from the SentinelX backend. Backend-generated audit records are displayed read-only.' : 'Sample audit records. In production the backend must generate tamper-resistant, access-controlled audit events — the browser cannot be a trusted source of audit data.'}</div>
      <Panel>
        <div className="flex flex-wrap items-center gap-2 border-b border-sx-line p-3">
          <SearchInput className="w-full sm:w-64" value={q} onChange={setQ} placeholder="Search action, target, source" label="Search audit log" />
          <Select label="User or service" className="w-40" value={user} onChange={setUser} options={[{ value: 'all', label: 'All users' }, ...users.map((u) => ({ value: u, label: u }))]} />
          <Select label="Action type" className="w-36" value={type} onChange={setType} options={[{ value: 'all', label: 'All actions' }, ...types.map((u) => ({ value: u, label: cap(u) }))]} />
          <Select label="Result" className="w-32" value={result} onChange={setResult} options={[{ value: 'all', label: 'All results' }, { value: 'success', label: 'Success' }, { value: 'failure', label: 'Failure' }, { value: 'denied', label: 'Denied' }]} />
          <Select label="Date range" className="w-36" value={date} onChange={setDate} options={[{ value: 'all', label: 'Any time' }, { value: '1', label: 'Last hour' }, { value: '24', label: 'Last 24 hours' }, { value: '168', label: 'Last 7 days' }]} />
        </div>
        {loading ? <LoadingState /> : error ? <ErrorState message={error} onRetry={reload} /> : list.length === 0 ? <EmptyState title="No audit records match" /> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] text-xs">
              <thead className="border-b border-sx-line bg-sx-bg/40"><tr>{['Timestamp', 'User / service', 'Action', 'Related case / asset', 'Result', 'Source'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
              <tbody className="divide-y divide-sx-line">
                {list.map((r) => (
                  <tr key={r.id} className="hover:bg-sx-elev/50">
                    <td className="td mono whitespace-nowrap text-sx-mute">{formatDateTime(r.time)}</td>
                    <td className="td"><span className="font-medium">{r.actor}</span> <span className="text-[10px] text-sx-mute">({r.actorType})</span></td>
                    <td className="td">{r.action}</td>
                    <td className="td mono text-sx-gold">{r.target}</td>
                    <td className="td"><StatusBadge value={r.result} /></td>
                    <td className="td text-sx-mute">{r.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}
