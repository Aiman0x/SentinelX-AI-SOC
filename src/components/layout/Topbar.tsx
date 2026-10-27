import { Bell, ChevronRight, Menu, RefreshCw, RotateCcw, User } from 'lucide-react';
import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useApp } from '../../context/AppContext';
import { useAlerts } from '../../hooks/useAlerts';
import { getBackendStatusView, type BackendStatusView } from '../../services/backendStatusService';
import { resetAllDemoData } from '../../services/miscService';
import { timeAgo } from '../../utils/formatDate';
import { SeverityBadge } from '../common/SeverityBadge';
import { SearchInput } from '../common/SearchInput';
import { navItems } from './nav';

function useClickAway(ref: React.RefObject<HTMLElement>, cb: () => void) {
  useEffect(() => {
    const h = (e: MouseEvent) => ref.current && !ref.current.contains(e.target as Node) && cb();
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [ref, cb]);
}

export function Topbar() {
  const { setMobileNavOpen, refresh, toast, openAlert, analyst } = useApp();
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const [q, setQ] = useState('');
  const [now, setNow] = useState(new Date());
  const [menu, setMenu] = useState<'none' | 'bell' | 'user'>('none');
  const [spin, setSpin] = useState(false);
  const [backendStatus, setBackendStatus] = useState<BackendStatusView>({ state: 'demo', label: 'DEMO MODE', detail: 'No backend URL is configured.' });
  const wrap = useRef<HTMLDivElement>(null);
  const { alerts } = useAlerts();

  useClickAway(wrap, () => setMenu('none'));

  const loadBackendStatus = () => {
    void getBackendStatusView().then(setBackendStatus);
  };

  useEffect(() => {
    loadBackendStatus();
  }, []);
  useEffect(() => {
    const t = window.setInterval(() => setNow(new Date()), 30000);
    return () => window.clearInterval(t);
  }, []);

  const current = navItems.find((n) => (n.end ? pathname === n.to : pathname.startsWith(n.to)));
  const critical = alerts.filter((a) => a.status === 'open' && (a.severity === 'critical' || a.severity === 'high')).slice(0, 4);

  const onSearch = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'Enter' && q.trim()) {
      navigate(`/alerts?q=${encodeURIComponent(q.trim())}`);
      setQ('');
    }
  };

  const doRefresh = () => {
    setSpin(true);
    refresh();
    loadBackendStatus();
    toast(backendStatus.state === 'demo' ? 'Demo data reloaded (no backend URL is configured).' : 'Refresh requested. Backend status is being checked; individual screens may still be pending.', 'info');
    window.setTimeout(() => setSpin(false), 600);
  };

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-sx-line bg-sx-bg/90 px-4 backdrop-blur">
      <button className="btn btn-ghost btn-sm lg:hidden" onClick={() => setMobileNavOpen(true)} aria-label="Open navigation">
        <Menu className="h-4 w-4" />
      </button>

      <nav aria-label="Breadcrumb" className="hidden min-w-0 items-center gap-1.5 text-xs text-sx-mute md:flex">
        <span>SentinelX</span>
        <ChevronRight className="h-3 w-3" aria-hidden />
        <span className="truncate font-medium text-sx-ink">{current?.label ?? 'Not found'}</span>
      </nav>

      <div className="mx-auto w-full max-w-md" onKeyDown={onSearch}>
        <SearchInput value={q} onChange={setQ} placeholder="Global search — press Enter to search alerts" label="Global search" />
      </div>

      <div className="ml-auto flex items-center gap-2" ref={wrap}>
        <span
          className={`hidden items-center gap-1.5 rounded-md border px-2 py-1 text-[10px] font-bold tracking-wider sm:inline-flex ${
            backendStatus.state === 'connected'
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
              : backendStatus.state === 'unavailable'
                ? 'border-sx-red/50 bg-sx-red/10 text-sx-red'
                : 'border-sx-gold/50 bg-sx-gold/10 text-sx-gold'
          }`}
          title={backendStatus.detail}
          aria-live="polite"
        >
          <span className={`h-1.5 w-1.5 rounded-full ${
            backendStatus.state === 'connected' ? 'bg-emerald-400' : backendStatus.state === 'unavailable' ? 'bg-sx-red' : 'bg-sx-gold'
          }`} aria-hidden />
          {backendStatus.label}
        </span>
        <time className="mono hidden text-[11px] text-sx-mute xl:block" dateTime={now.toISOString()}>
          {now.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })} · {now.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}
        </time>

        <button className="btn btn-sm" onClick={doRefresh} aria-label="Refresh data">
          <RefreshCw className={`h-3.5 w-3.5 ${spin ? 'animate-spin' : ''}`} /> <span className="hidden md:inline">Refresh</span>
        </button>

        <div className="relative">
          <button className="btn btn-sm relative" onClick={() => setMenu(menu === 'bell' ? 'none' : 'bell')} aria-label="Notifications" aria-expanded={menu === 'bell'}>
            <Bell className="h-3.5 w-3.5" />
            {critical.length > 0 && <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-sx-red px-1 text-[9px] font-bold text-white">{critical.length}</span>}
          </button>
          {menu === 'bell' && (
            <div className="anim-fade absolute right-0 mt-2 w-80 overflow-hidden rounded-xl border border-sx-line bg-sx-panel shadow-2xl">
              <div className="border-b border-sx-line px-3 py-2 text-xs font-semibold">Open high-priority alerts <span className="font-normal text-sx-gold">(demo)</span></div>
              {critical.length === 0 && <div className="px-3 py-6 text-center text-xs text-sx-mute">No open high-priority alerts.</div>}
              {critical.map((a) => (
                <button key={a.id} className="flex w-full flex-col gap-1 border-b border-sx-line px-3 py-2 text-left last:border-0 hover:bg-sx-elev" onClick={() => { setMenu('none'); openAlert(a.id); }}>
                  <span className="flex items-center justify-between"><SeverityBadge severity={a.severity} /><span className="text-[10px] text-sx-mute">{timeAgo(a.timestamp)}</span></span>
                  <span className="text-xs">{a.ruleName}</span>
                  <span className="mono text-[11px] text-sx-mute">{a.asset}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="relative">
          <button className="btn btn-sm" onClick={() => setMenu(menu === 'user' ? 'none' : 'user')} aria-label="Analyst menu" aria-expanded={menu === 'user'}>
            <span className="flex h-5 w-5 items-center justify-center rounded-full bg-sx-reddark text-[10px] font-bold">{analyst[0]}</span>
            <span className="hidden md:inline">{analyst}</span>
          </button>
          {menu === 'user' && (
            <div className="anim-fade absolute right-0 mt-2 w-56 overflow-hidden rounded-xl border border-sx-line bg-sx-panel shadow-2xl">
              <div className="border-b border-sx-line px-3 py-2.5">
                <div className="text-xs font-semibold">{analyst}</div>
                <div className="text-[11px] text-sx-mute">SOC Analyst (demo profile)</div>
              </div>
              <button className="flex w-full items-center gap-2 px-3 py-2 text-xs hover:bg-sx-elev" onClick={() => { setMenu('none'); navigate('/settings'); }}><User className="h-3.5 w-3.5" /> Profile & settings</button>
              <button className="flex w-full items-center gap-2 px-3 py-2 text-xs text-sx-warn hover:bg-sx-elev" onClick={() => { setMenu('none'); resetAllDemoData(); }}><RotateCcw className="h-3.5 w-3.5" /> Reset demo data</button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
