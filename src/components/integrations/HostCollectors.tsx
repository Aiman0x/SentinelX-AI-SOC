import { useEffect, useMemo, useState } from 'react';
import { apiDelete, apiGet, apiPost, isBackendConfigured } from '../../services/apiClient';

type Platform = 'windows' | 'linux';
type Collector = { id: string; name: string; platform: string; createdAt: string; lastSeenAt: string | null; status: 'online' | 'stale' | 'pending' | 'paused' };
export function HostCollectors() {
  const [items, setItems] = useState<Collector[]>([]);
  const [platform, setPlatform] = useState<Platform>('linux');
  const [name, setName] = useState('Wazuh Linux VM');
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [actionBusyId, setActionBusyId] = useState('');
  const [error, setError] = useState('');
  const apiUrl = import.meta.env.VITE_API_BASE_URL || 'https://sentinelx-api-gateway.aiman132046.workers.dev';
  const windowsScriptUrl = 'https://raw.githubusercontent.com/Aiman0x/SentinelX-AI-SOC/main/scripts/SentinelX_Local_Windows_Collector.ps1';
  const linuxInstallerUrl = 'https://raw.githubusercontent.com/Aiman0x/SentinelX-AI-SOC/main/scripts/wazuh-poller/install.sh';
  const installCommand = useMemo(() => platform === 'windows'
    ? `$env:SENTINELX_COLLECTOR_API_URL = "${apiUrl}"
$env:SENTINELX_COLLECTOR_TOKEN = "${token}"
$script = Join-Path $env:TEMP "SentinelX_Local_Windows_Collector.ps1"
Invoke-WebRequest -Uri "${windowsScriptUrl}" -OutFile $script
& $script -Continuous`
    : `curl -fsSL "${linuxInstallerUrl}" -o /tmp/sentinelx-wazuh-install.sh
sudo bash /tmp/sentinelx-wazuh-install.sh`, [platform, apiUrl, token, windowsScriptUrl, linuxInstallerUrl]);
  const load = async () => {
    if (!isBackendConfigured) return;
    try { const data = await apiGet<{ collectors: Collector[] }>('/api/collectors'); setItems(data.collectors || []); }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not load enrolled hosts.'); }
  };
  useEffect(() => { void load(); }, []);
  const changePlatform = (next: Platform) => {
    setPlatform(next);
    setName(next === 'linux' ? 'Wazuh Linux VM' : 'My Windows PC');
    setToken('');
  };
  const create = async () => {
    setBusy(true); setError(''); setToken('');
    try {
      const data = await apiPost<{ token: string }>('/api/collectors', { name, platform });
      setToken(data.token); await load();
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not enroll host.'); }
    finally { setBusy(false); }
  };
  const togglePause = async (id: string, paused: boolean) => {
    setActionBusyId(id); setError('');
    try { await apiPost('/api/collectors/' + id + (paused ? '/resume' : '/pause'), {}); await load(); }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not update collector state.'); }
    finally { setActionBusyId(''); }
  };
  const revoke = async (id: string) => {
    setActionBusyId(id); setError('');
    try { await apiDelete('/api/collectors/' + id); await load(); }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not remove collector.'); }
    finally { setActionBusyId(''); }
  };
  return <section className="panel mb-5 p-4">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><h2 className="text-sm font-semibold">Host collectors</h2><p className="mt-1 text-xs text-sx-mute">Connect Windows endpoints or your Linux Wazuh server using one secure enrollment.</p></div>
      <span className="rounded border border-sx-gold/30 px-2 py-1 text-[10px] text-sx-gold">Outbound HTTPS · read-only</span>
    </div>
    {!isBackendConfigured ? <p className="mt-3 text-xs text-sx-warn">SentinelX backend is not configured.</p> : <>
      <div className="mt-3 grid gap-2 md:grid-cols-[1fr_1fr_auto]">
        <select className="input" value={platform} onChange={e=>changePlatform(e.target.value as Platform)} aria-label="Host type">
          <option value="windows">Windows endpoint</option>
          <option value="linux">Linux · Wazuh server</option>
        </select>
        <input className="input" value={name} onChange={e=>setName(e.target.value)} placeholder="Host name" aria-label="Host name" />
        <button className="btn btn-primary" disabled={busy || name.trim().length<2} onClick={()=>void create()}>{busy ? 'Enrolling…' : 'Enroll host'}</button>
      </div>
      {token && <div className="mt-3 rounded border border-sx-gold/40 bg-sx-gold/5 p-3">
        <p className="text-xs font-semibold text-sx-gold">One-time setup</p>
        {platform === 'linux'
          ? <><p className="mt-1 text-[10px] leading-5 text-sx-mute">On your Wazuh Linux VM, run this command. The installer will securely prompt for the one-time collector token and your read-only Wazuh API/Indexer credentials. Those credentials stay on the VM; they are never entered into the SentinelX website.</p></>
          : <p className="mt-1 text-[10px] text-sx-mute">Open PowerShell as Administrator on that Windows PC. This command contains its private collector token; do not share it.</p>}
        <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-all rounded bg-sx-bg p-2 text-[10px]">{installCommand}</pre>
        <button className="btn mt-2" onClick={()=>void navigator.clipboard.writeText(installCommand)}>Copy setup command</button>
        {platform === 'windows' && <p className="mt-2 text-[10px] text-sx-mute">The collector starts continuous monitoring. Stop it with Ctrl+C to remove this host enrollment automatically.</p>}
        {platform === 'linux' && <p className="mt-2 text-[10px] text-sx-mute">Wazuh Manager and Indexer ports remain private. The poller sends alerts to SentinelX over HTTPS every minute. You can stop it from this page using Pause or Remove.</p>}
      </div>}
      {error && <p className="mt-2 text-xs text-sx-warn">{error}</p>}
      <div className="mt-4 space-y-2">
        {items.map(item=><div key={item.id} className="flex flex-wrap items-center justify-between gap-2 rounded border border-sx-line bg-sx-bg p-2 text-xs">
          <div><span className="font-medium">{item.name}</span><span className="ml-2 text-sx-mute">{item.platform === 'linux' ? 'Linux · Wazuh' : item.platform}</span><div className="mt-1 text-[10px] text-sx-mute">Last event/heartbeat: {item.lastSeenAt ? new Date(item.lastSeenAt).toLocaleString() : 'Waiting for first connection'}</div></div>
          <div className="flex flex-wrap items-center gap-2">
            <span className={item.status==='online'?'text-sx-green':item.status==='paused'?'text-sx-mute':'text-sx-warn'}>{item.status}</span>
            <button className="btn" disabled={actionBusyId===item.id} onClick={()=>void togglePause(item.id,item.status==='paused')}>{actionBusyId===item.id?'Updating…':item.status==='paused'?'Resume':'Pause'}</button>
            <button className="btn" disabled={actionBusyId===item.id} onClick={()=>void revoke(item.id)}>Remove</button>
          </div>
        </div>)}
        {!items.length && <p className="text-xs text-sx-mute">No hosts enrolled yet.</p>}
      </div>
    </>}
  </section>;
}
