import { useEffect, useState } from 'react';
import { apiDelete, apiGet, apiPost, isBackendConfigured } from '../../services/apiClient';

type Collector = { id: string; name: string; platform: string; createdAt: string; lastSeenAt: string | null; status: 'online' | 'stale' | 'pending' | 'revoked' };
export function HostCollectors() {
  const [items, setItems] = useState<Collector[]>([]);
  const [name, setName] = useState('My security host');
  const [platform, setPlatform] = useState('windows');
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const apiUrl = import.meta.env.VITE_API_BASE_URL || 'https://sentinelx-api-gateway.aiman132046.workers.dev';
  const windowsCommand = `$env:SENTINELX_COLLECTOR_API_URL = "${apiUrl}"\n$env:SENTINELX_COLLECTOR_TOKEN = "${token}"\n.\\SentinelX_Local_Windows_Collector.ps1`;
  const windowsContinuousCommand = `${windowsCommand} -Continuous -IntervalSeconds 30`;
  const pythonCommand = `$env:SENTINELX_URL = "${apiUrl}"\n$env:SENTINELX_COLLECTOR_TOKEN = "${token}"\npython .\\sentinelx_collector.py --once`;
  const load = async () => {
    if (!isBackendConfigured) return;
    try { const data = await apiGet<{ collectors: Collector[] }>('/api/collectors'); setItems(data.collectors || []); }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not load collectors.'); }
  };
  useEffect(() => { void load(); }, []);
  const create = async () => {
    setBusy(true); setError(''); setToken('');
    try {
      const data = await apiPost<{ token: string }>('/api/collectors', { name, platform });
      setToken(data.token); await load();
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not create collector.'); }
    finally { setBusy(false); }
  };
  const revoke = async (id: string) => {
    try { await apiDelete('/api/collectors/' + id); await load(); }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not revoke collector.'); }
  };
  return <section className="panel mb-5 p-4">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><h2 className="text-sm font-semibold">Host Collectors</h2><p className="mt-1 text-xs text-sx-mute">Enroll customer-owned Windows/Linux hosts. The collector performs read-only checks and sends health over outbound HTTPS.</p></div>
      <span className="rounded border border-sx-gold/30 px-2 py-1 text-[10px] text-sx-gold">Tenant-scoped credentials</span>
    </div>
    {!isBackendConfigured ? <p className="mt-3 text-xs text-sx-warn">Connect the SentinelX backend to enroll collectors.</p> : <>
      <div className="mt-3 grid gap-2 md:grid-cols-[1fr_150px_auto]">
        <input className="input" value={name} onChange={e=>setName(e.target.value)} placeholder="Collector name" aria-label="Collector name" />
        <select className="input" value={platform} onChange={e=>setPlatform(e.target.value)} aria-label="Collector platform"><option value="windows">Windows</option><option value="linux">Linux</option><option value="macos">macOS</option><option value="other">Other</option></select>
        <button className="btn btn-primary" disabled={busy || name.trim().length<2} onClick={()=>void create()}>{busy ? 'Creating…' : 'Create collector'}</button>
      </div>
      {token && <div className="mt-3 rounded border border-sx-gold/40 bg-sx-gold/5 p-3">
        <p className="text-xs font-semibold text-sx-gold">One-time collector token — copy it now</p>
        <code className="mt-2 block break-all text-xs">{token}</code>
        <button className="btn mt-2" onClick={()=>void navigator.clipboard.writeText(token)}>Copy token</button>
        <p className="mt-2 text-[10px] text-sx-mute">Token is shown only once. Store it in an environment variable; never commit it to source control.</p>
        {platform === 'windows' && <div className="mt-4 space-y-3">
          <div>
            <p className="text-xs font-semibold">Windows Security Event ID 4625</p>
            <p className="mt-1 text-[10px] text-sx-mute">Run PowerShell as Administrator. One-time run:</p>
            <pre className="mt-2 overflow-x-auto whitespace-pre-wrap rounded bg-sx-bg p-2 text-[10px]">{windowsCommand}</pre>
            <button className="btn mt-2" onClick={()=>void navigator.clipboard.writeText(windowsCommand)}>Copy Windows command</button>
            <p className="mt-2 text-[10px] text-sx-mute">Continuous mode:</p>
            <pre className="mt-2 overflow-x-auto whitespace-pre-wrap rounded bg-sx-bg p-2 text-[10px]">{windowsContinuousCommand}</pre>
            <button className="btn mt-2" onClick={()=>void navigator.clipboard.writeText(windowsContinuousCommand)}>Copy continuous command</button>
            <p className="mt-1 text-[10px] text-sx-mute">Stop locally with Ctrl+C. Revoke blocks future requests but does not remotely terminate the process.</p>
          </div>
          <div>
            <p className="text-xs font-semibold">Python host-health checks</p>
            <pre className="mt-2 overflow-x-auto whitespace-pre-wrap rounded bg-sx-bg p-2 text-[10px]">{pythonCommand}</pre>
            <button className="btn mt-2" onClick={()=>void navigator.clipboard.writeText(pythonCommand)}>Copy Python command</button>
          </div>
        </div>}
      </div>}
      {error && <p className="mt-2 text-xs text-sx-warn">{error}</p>}
      <div className="mt-4 space-y-2">
        {items.map(item=><div key={item.id} className="flex flex-wrap items-center justify-between gap-2 rounded border border-sx-line bg-sx-bg p-2 text-xs">
          <div><span className="font-medium">{item.name}</span><span className="ml-2 text-sx-mute">{item.platform}</span><div className="mt-1 text-[10px] text-sx-mute">Last heartbeat: {item.lastSeenAt ? new Date(item.lastSeenAt).toLocaleString() : 'Never'}</div></div>
          <div className="flex items-center gap-2"><span className={item.status==='online'?'text-sx-green':item.status==='revoked'?'text-sx-red':'text-sx-warn'}>{item.status}</span>{item.status!=='revoked' && <button className="btn" onClick={()=>void revoke(item.id)}>Revoke</button>}</div>
        </div>)}
        {!items.length && <p className="text-xs text-sx-mute">No collectors enrolled yet.</p>}
      </div>
      <p className="mt-3 text-[10px] text-sx-mute">Windows 4625 and Python health collectors are available in the repository. Use the commands above or see <code>docs/HOST_COLLECTOR_SETUP.md</code>.</p>
    </>}
  </section>;
}
