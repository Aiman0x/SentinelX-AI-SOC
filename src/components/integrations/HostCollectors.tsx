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
type Bridge = { id: string; name: string; platform: string; createdAt: string; lastSeenAt: string | null; status: string };
type BridgeList = { bridges: Bridge[] };
type CreateResult = { created: boolean; collector: Collector; token: string; warning: string };

export function HostCollectors() {
  const [collectors, setCollectors] = useState<Collector[]>([]);
  const [bridges, setBridges] = useState<Bridge[]>([]);
  const [bridgeName, setBridgeName] = useState('');
  const [bridgePlatform, setBridgePlatform] = useState('windows');
  const [bridgeToken, setBridgeToken] = useState('');
  const [name, setName] = useState('');
  const [platform, setPlatform] = useState('windows');
  const [loading, setLoading] = useState(false);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState('');
  const [token, setToken] = useState('');
  const [copyState, setCopyState] = useState('');
  const [mcpUrl, setMcpUrl] = useState('');
  const [mcpToken, setMcpToken] = useState('');
  const [mcpLabel, setMcpLabel] = useState('Security MCP');
  const [mcpTools, setMcpTools] = useState<Array<{name:string;description?:string;readOnly:boolean;inputSchema?:unknown}>>([]);
  const [mcpTool, setMcpTool] = useState('');
  const [mcpArgs, setMcpArgs] = useState('{}');
  const [mcpBusy, setMcpBusy] = useState(false);
  const [mcpResult, setMcpResult] = useState('');

  const saveMcp = async (event: FormEvent) => {
    event.preventDefault(); setMcpBusy(true); setError('');
    try { await apiPost('/api/mcp/connect', { label: mcpLabel, serverUrl: mcpUrl, bearerToken: mcpToken }); setMcpToken(''); setMcpResult('MCP endpoint saved. Discover tools to verify it.'); }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not save MCP server.'); }
    finally { setMcpBusy(false); }
  };
  const discoverMcp = async () => {
    setMcpBusy(true); setError(''); setMcpResult('');
    try { const response = await apiPost<{ok:boolean;data:{tools:Array<{name:string;description?:string;readOnly:boolean;inputSchema?:unknown}>;total:number;readOnlyTools:number}}>('/api/mcp/test', {}); setMcpTools(response.data.tools ?? []); setMcpTool(response.data.tools?.find(t => t.readOnly)?.name ?? ''); setMcpResult(`Discovered ${response.data.total} tools; ${response.data.readOnlyTools} explicitly marked read-only.`); }
    catch (e) { setError(e instanceof Error ? e.message : 'MCP discovery failed.'); }
    finally { setMcpBusy(false); }
  };
  const runMcpTool = async () => {
    let args: unknown; try { args = JSON.parse(mcpArgs || '{}'); } catch { setError('Tool arguments must be valid JSON.'); return; }
    if (!args || typeof args !== 'object' || Array.isArray(args)) { setError('Tool arguments must be a JSON object.'); return; }
    setMcpBusy(true); setError('');
    try { const response = await apiPost<{data:unknown}>('/api/mcp/call', { toolName: mcpTool, arguments: args }); setMcpResult(JSON.stringify(response.data, null, 2)); }
    catch (e) { setError(e instanceof Error ? e.message : 'MCP tool call failed.'); }
    finally { setMcpBusy(false); }
  };

  const load = async () => {
    if (!isBackendConfigured) return;
    setLoading(true);
    setError('');
    try {
      const [result, bridgeResult] = await Promise.all([apiGet<CollectorList>('/api/collectors'), apiGet<BridgeList>('/api/bridges')]);
      setCollectors(result.collectors ?? []);
      setBridges(bridgeResult.bridges ?? []);
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

  const createBridge = async (event: FormEvent) => {
    event.preventDefault();
    if (bridgeName.trim().length < 2) { setError('Enter a bridge name with at least 2 characters.'); return; }
    setCreating(true); setError(''); setBridgeToken('');
    try {
      const result = await apiPost<{ token: string }>('/api/bridges', { name: bridgeName.trim(), platform: bridgePlatform });
      setBridgeToken(result.token); setBridgeName(''); await load();
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not enroll local bridge.'); }
    finally { setCreating(false); }
  };
  const revokeBridge = async (bridge: Bridge) => {
    if (!window.confirm(`Revoke local bridge "${bridge.name}"? Its token will stop working immediately.`)) return;
    try { await apiDelete(`/api/bridges/${bridge.id}`); await load(); }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not revoke bridge.'); }
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

  const copyBridge = async () => {
    try { await navigator.clipboard.writeText(bridgeToken); setCopyState('Copied'); }
    catch { setCopyState('Select and copy the token manually.'); }
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

      <div className="mt-5 rounded-lg border border-sx-line bg-sx-bg/40 p-3">
        <div className="text-sm font-semibold">MCP server — read-only discovery</div>
        <p className="mt-1 text-xs text-sx-mute">Connect a customer-owned MCP Streamable HTTP endpoint. Private/local endpoints are reached through the enrolled Local Bridge; no tunnel or inbound port is required.</p>
        <form onSubmit={saveMcp} className="mt-3 grid gap-2 sm:grid-cols-2">
          <input className="input" value={mcpLabel} onChange={e => setMcpLabel(e.target.value)} placeholder="Server label" maxLength={80} />
          <input className="input" type="url" value={mcpUrl} onChange={e => setMcpUrl(e.target.value)} placeholder="http://127.0.0.1:3000/mcp" required />
          <input className="input sm:col-span-2" type="password" value={mcpToken} onChange={e => setMcpToken(e.target.value)} placeholder="Optional bearer token (leave blank to keep saved token)" autoComplete="new-password" />
          <button className="btn btn-primary sm:col-span-2" type="submit" disabled={mcpBusy || !mcpUrl.trim()}>Save MCP endpoint</button>
        </form>
        <div className="mt-2 flex flex-wrap gap-2">
          <button type="button" className="btn btn-gold" onClick={() => void discoverMcp()} disabled={mcpBusy}>Discover MCP tools</button>
          <span className="self-center text-[10px] text-sx-mute">Only tools declaring annotations.readOnlyHint=true can be run.</span>
        </div>
        {mcpTools.length > 0 && <div className="mt-3 space-y-2">
          <div className="text-xs font-semibold">Discovered tools</div>
          {mcpTools.map(tool => <div key={tool.name} className="rounded border border-sx-line p-2 text-xs">
            <div className="flex items-center justify-between gap-2"><span className="font-semibold">{tool.name}</span><span className={tool.readOnly ? 'text-sx-green' : 'text-sx-warn'}>{tool.readOnly ? 'Read-only' : 'Blocked · not marked read-only'}</span></div>
            {tool.description && <p className="mt-1 text-[10px] text-sx-mute">{tool.description}</p>}
          </div>)}
          {mcpTools.some(t => t.readOnly) && <div className="grid gap-2 sm:grid-cols-2">
            <select className="input" value={mcpTool} onChange={e => setMcpTool(e.target.value)}><option value="">Choose read-only tool</option>{mcpTools.filter(t => t.readOnly).map(t => <option key={t.name} value={t.name}>{t.name}</option>)}</select>
            <textarea className="input min-h-20 font-mono text-xs sm:col-span-2" value={mcpArgs} onChange={e => setMcpArgs(e.target.value)} placeholder='{"key":"value"}' />
            <button type="button" className="btn btn-gold sm:col-span-2" onClick={() => void runMcpTool()} disabled={mcpBusy || !mcpTool}>Run selected read-only tool</button>
          </div>}
        </div>}
        {mcpResult && <pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded border border-sx-line bg-sx-bg p-2 text-[10px]">{mcpResult}</pre>}
      </div>

      <div className="mt-5 rounded-lg border border-sx-gold/25 bg-sx-gold/5 p-3">
        <div className="text-sm font-semibold">Local Bridge — private network access</div>
        <p className="mt-1 text-xs text-sx-mute">Run this outbound-only bridge on a Windows, Linux, or macOS machine that can reach your private tools. No inbound port and no Cloudflare Tunnel required.</p>
        <form onSubmit={createBridge} className="mt-3 grid gap-2 sm:grid-cols-[1fr_150px_auto]">
          <input className="input" value={bridgeName} onChange={e => setBridgeName(e.target.value)} placeholder="Bridge name (e.g. Office-SOC-Bridge)" maxLength={80} />
          <select className="input" value={bridgePlatform} onChange={e => setBridgePlatform(e.target.value)}>
            <option value="windows">Windows</option><option value="linux">Linux</option><option value="macos">macOS</option>
          </select>
          <button className="btn btn-gold" type="submit" disabled={creating}><Plus className="h-3.5 w-3.5" /> Enroll bridge</button>
        </form>
        {bridgeToken && <div className="mt-3 rounded border border-sx-gold/30 p-2">
          <div className="text-xs font-semibold text-sx-gold">Bridge token — copy once</div>
          <code className="mt-2 block break-all rounded bg-sx-bg p-2 text-[11px]">{bridgeToken}</code>
          <button type="button" className="btn btn-gold mt-2" onClick={() => void copyBridge()}><Copy className="h-3.5 w-3.5" /> Copy token</button>
          <span className="ml-2 text-[11px] text-sx-mute">{copyState}</span>
          <p className="mt-2 text-[11px] text-sx-mute">Store this token in the bridge config file. It will not be displayed again.</p>
        </div>}
        <div className="mt-3 overflow-x-auto">
          <table className="w-full min-w-[460px] text-left text-xs">
            <thead className="border-b border-sx-line text-sx-mute"><tr><th className="py-2">Bridge</th><th>Platform</th><th>Status</th><th>Last seen</th><th></th></tr></thead>
            <tbody>
              {bridges.map(bridge => <tr key={bridge.id} className="border-b border-sx-line/70"><td className="py-2 font-medium">{bridge.name}</td><td className="text-sx-mute">{bridge.platform}</td><td><StatusBadge value={bridge.status} /></td><td className="text-sx-mute">{bridge.lastSeenAt ? new Date(bridge.lastSeenAt).toLocaleString() : 'Never'}</td><td className="text-right">{bridge.status !== 'revoked' && <button type="button" className="btn btn-danger" onClick={() => void revokeBridge(bridge)}><Trash2 className="h-3 w-3" /> Revoke</button>}</td></tr>)}
              {!bridges.length && <tr><td colSpan={5} className="py-3 text-center text-sx-mute">No local bridges enrolled.</td></tr>}
            </tbody>
          </table>
        </div>
        <p className="mt-2 text-[10px] text-sx-mute">The bridge supports read-only Wazuh queries and MCP Streamable HTTP discovery. MCP stdio servers are not supported yet.</p>
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
