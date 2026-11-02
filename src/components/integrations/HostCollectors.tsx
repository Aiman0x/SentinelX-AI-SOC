import { useEffect, useState, type FormEvent } from 'react';
import { Copy, Plus, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react';
import { Panel } from '../common/Controls';
import { StatusBadge } from '../common/StatusBadge';
import { apiDelete, apiGet, apiPost, isBackendConfigured } from '../../services/apiClient';

type Collector = {
  id: string;
  name: string;
  platform: string;
  createdAt: string;
  lastSeenAt: string | null;
  status: 'pending' | 'online' | 'stale' | 'revoked' | string;
};
type CollectorList = { collectors: Collector[] };
type CreateResult = { created: boolean; collector: Collector; token: string; warning: string };

export function HostCollectors() {
  const [collectors, setCollectors] = useState<Collector[]>([]);
  const [name, setName] = useState('');
  const [platform, setPlatform] = useState('windows');
  const [loading, setLoading] = useState(false);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState('');
  const [token, setToken] = useState('');
  const [copyState, setCopyState] = useState('');

  const load = async () => {
    if (!isBackendConfigured) return;
    setLoading(true);
    setError('');
    try {
      const result = await apiGet<CollectorList>('/api/collectors');
      setCollectors(result.collectors ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load host collectors.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, []);

  const create = async (event: FormEvent) => {
    event.preventDefault();
    if (name.trim().length < 2) { setError('Enter a collector name with at least 2 characters.'); return; }
    setCreating(true);
    setError('');
    setToken('');
    try {
      const result = await apiPost<CreateResult>('/api/collectors', { name: name.trim(), platform });
      setToken(result.token);
      setName('');
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not create collector.');
    } finally {
      setCreating(false);
    }
  };

  const revoke = async (collector: Collector) => {
    if (!window.confirm(`Revoke collector "${collector.name}"? Its token will stop working immediately.`)) return;
    setError('');
    try {
      await apiDelete<{ revoked: boolean }>(`/api/collectors/${collector.id}`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not revoke collector.');
    }
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(token);
      setCopyState('Copied');
    } catch {
      setCopyState('Select and copy the token manually.');
    }
  };

  if (!isBackendConfigured) {
    return (
      <Panel bodyClass="p-4" className="mb-4">
        <div className="flex items-center gap-2 text-sm font-semibold"><ShieldCheck className="h-4 w-4 text-sx-gold" /> Host collectors</div>
        <p className="mt-2 text-xs text-sx-mute">Connect the authenticated SentinelX backend to enroll tenant-scoped Windows, Linux, or macOS collectors.</p>
      </Panel>
    );
  }

  return (
    <Panel bodyClass="p-4" className="mb-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 text-sm font-semibold"><ShieldCheck className="h-4 w-4 text-sx-gold" /> Host collectors</div>
          <p className="mt-1 text-xs text-sx-mute">Each collector gets a unique organization-scoped token. Tokens are shown only once.</p>
        </div>
        <button className="btn" onClick={() => void load()} disabled={loading}><RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh</button>
      </div>

      <form onSubmit={create} className="mt-4 grid gap-2 sm:grid-cols-[1fr_150px_auto]">
        <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Collector name (e.g. Aiman-Windows-01)" maxLength={80} />
        <select className="input" value={platform} onChange={(e) => setPlatform(e.target.value)}>
          <option value="windows">Windows</option><option value="linux">Linux</option><option value="macos">macOS</option><option value="other">Other</option>
        </select>
        <button className="btn btn-primary" type="submit" disabled={creating}><Plus className="h-3.5 w-3.5" /> {creating ? 'Creating…' : 'Create collector'}</button>
      </form>

      {error && <p className="mt-3 rounded border border-sx-red/30 bg-sx-red/5 p-2 text-xs text-sx-red">{error}</p>}

      {token && (
        <div className="mt-4 rounded border border-sx-gold/35 bg-sx-gold/5 p-3">
          <div className="text-xs font-semibold text-sx-gold">New collector token — copy it now</div>
          <code className="mt-2 block break-all rounded bg-sx-bg p-2 text-[11px] text-sx-text">{token}</code>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <button type="button" className="btn btn-gold" onClick={() => void copy()}><Copy className="h-3.5 w-3.5" /> Copy token</button>
            <span className="text-[11px] text-sx-mute">{copyState || 'It cannot be retrieved after you leave this screen.'}</span>
          </div>
          <p className="mt-3 text-[11px] text-sx-mute">Configure your collector with this token as <code>SENTINELX_ORG_TOKEN</code> and send it in the <code>X-SentinelX-Org-Key</code> header alongside the existing <code>X-SentinelX-Key</code> webhook header.</p>
        </div>
      )}

      <div className="mt-4 overflow-x-auto">
        <table className="w-full min-w-[540px] text-left text-xs">
          <thead className="border-b border-sx-line text-sx-mute"><tr><th className="py-2">Collector</th><th>Platform</th><th>Status</th><th>Last seen</th><th></th></tr></thead>
          <tbody>
            {collectors.map((collector) => (
              <tr key={collector.id} className="border-b border-sx-line/70">
                <td className="py-2 font-medium">{collector.name}</td>
                <td className="text-sx-mute">{collector.platform}</td>
                <td><StatusBadge value={collector.status} /></td>
                <td className="text-sx-mute">{collector.lastSeenAt ? new Date(collector.lastSeenAt).toLocaleString() : 'Never'}</td>
                <td className="text-right">{collector.status !== 'revoked' && <button type="button" className="btn btn-danger" onClick={() => void revoke(collector)}><Trash2 className="h-3 w-3" /> Revoke</button>}</td>
              </tr>
            ))}
            {!collectors.length && <tr><td colSpan={5} className="py-4 text-center text-sx-mute">{loading ? 'Loading collectors…' : 'No host collectors enrolled.'}</td></tr>}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}
