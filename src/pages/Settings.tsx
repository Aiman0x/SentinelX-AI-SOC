import { Bell, Database, Info, Lock, Palette, Plug, SlidersHorizontal, User, type LucideIcon } from 'lucide-react';
import { useState } from 'react';
import { Field, Panel, Select } from '../components/common/Controls';
import { PageHeader } from '../components/layout/PageHeader';
import { APP_VERSION } from '../components/layout/Sidebar';
import { useApp } from '../context/AppContext';
import { API_BASE_URL, ENVIRONMENT_LABEL, isBackendConfigured } from '../services/apiClient';
import { resetAllDemoData } from '../services/miscService';
import { createLocalStore } from '../services/localStore';
import { useLocalStore } from '../hooks/useLocalStore';

interface Prefs { compact: boolean; confirmDisruptive: boolean; notifyCritical: boolean; notifyCase: boolean; notifyDigest: boolean; retention: string; timeFormat: string; }
const prefsStore = createLocalStore<Prefs>('sentinelx.ui.prefs.v1', () => ({ compact: false, confirmDisruptive: true, notifyCritical: true, notifyCase: true, notifyDigest: false, retention: '90', timeFormat: '24h' }));

const sections: { id: string; label: string; icon: LucideIcon }[] = [
  { id: 'app', label: 'Application preferences', icon: SlidersHorizontal },
  { id: 'theme', label: 'Theme & appearance', icon: Palette },
  { id: 'profile', label: 'Analyst profile', icon: User },
  { id: 'notify', label: 'Notification preferences', icon: Bell },
  { id: 'integrations', label: 'Integration settings', icon: Plug },
  { id: 'retention', label: 'Data retention', icon: Database },
  { id: 'security', label: 'Security & access control', icon: Lock },
  { id: 'about', label: 'About SentinelX', icon: Info },
];

function Toggle({ label, desc, checked, onChange, disabled }: { label: string; desc?: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 py-3">
      <div><div className="text-xs font-medium">{label}</div>{desc && <div className="text-[11px] text-sx-mute">{desc}</div>}</div>
      <button role="switch" aria-checked={checked} aria-label={label} disabled={disabled} onClick={() => onChange(!checked)}
        className={`relative h-5 w-9 shrink-0 rounded-full border transition-colors disabled:opacity-60 ${checked ? 'border-sx-red/60 bg-sx-reddark' : 'border-sx-line bg-sx-elev'}`}>
        <span className={`absolute top-0.5 h-3.5 w-3.5 rounded-full bg-white transition-all ${checked ? 'left-[18px]' : 'left-0.5'}`} />
      </button>
    </div>
  );
}

export default function Settings() {
  const prefs = useLocalStore(prefsStore);
  const { toast, analyst } = useApp();
  const [active, setActive] = useState('app');
  const set = (p: Partial<Prefs>) => prefsStore.set({ ...prefs, ...p });
  const sec = sections.find((s) => s.id === active)!;

  return (
    <>
      <PageHeader title="Settings" subtitle="Preferences are stored in this browser only." demo={false} />
      <div className="grid gap-4 lg:grid-cols-[240px_minmax(0,1fr)]">
        <nav aria-label="Settings sections" className="panel h-fit p-2">
          {sections.map((s) => (
            <button key={s.id} onClick={() => setActive(s.id)} aria-current={active === s.id}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-xs transition-colors ${active === s.id ? 'bg-sx-reddark/25 text-sx-ink' : 'text-sx-mute hover:bg-sx-elev hover:text-sx-ink'}`}>
              <s.icon className={`h-4 w-4 ${active === s.id ? 'text-sx-gold' : ''}`} /> {s.label}
            </button>
          ))}
        </nav>

        <Panel title={sec.label} bodyClass="divide-y divide-sx-line px-4">
          {active === 'app' && (<>
            <Toggle label="Compact tables" desc="Reduce row spacing (preview setting)." checked={prefs.compact} onChange={(v) => set({ compact: v })} />
            <Toggle label="Require typed confirmation for disruptive actions" desc="Always on in this prototype; cannot be disabled." checked disabled onChange={() => undefined} />
            <div className="py-3"><Field label="Time format"><Select label="Time format" className="w-40" value={prefs.timeFormat} onChange={(v) => set({ timeFormat: v })} options={[{ value: '24h', label: '24-hour' }, { value: '12h', label: '12-hour' }]} /></Field></div>
          </>)}
          {active === 'theme' && (
            <div className="space-y-4 py-4">
              <p className="text-xs text-sx-mute">The default SentinelX theme is black, red and gold. Alternative themes are not enabled in this prototype.</p>
              <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
                {[['Background', '#090909'], ['Sidebar', '#0D0D0D'], ['Panel', '#141414'], ['Red', '#E53935'], ['Dark red', '#8F1D1D'], ['Gold', '#D4AF37']].map(([n, c]) => (
                  <div key={n} className="text-center"><div className="h-12 rounded-lg border border-sx-line" style={{ background: c }} /><div className="mt-1 text-[10px] text-sx-mute">{n}</div><div className="mono text-[10px]">{c}</div></div>
                ))}
              </div>
              <div className="rounded-lg border border-sx-gold/40 bg-sx-gold/5 px-3 py-2 text-xs text-sx-gold">Active theme: SentinelX Black · Red · Gold (default)</div>
            </div>
          )}
          {active === 'profile' && (
            <div className="grid gap-3 py-4 sm:grid-cols-2">
              <Field label="Display name"><input className="input" value={analyst} readOnly aria-label="Display name" /></Field>
              <Field label="Role"><input className="input" value="SOC Analyst (demo profile)" readOnly aria-label="Role" /></Field>
              <p className="text-[11px] text-sx-mute sm:col-span-2">Identity and roles will come from the backend authentication provider.</p>
            </div>
          )}
          {active === 'notify' && (<>
            <Toggle label="Critical alerts" desc="Notify when a critical alert opens." checked={prefs.notifyCritical} onChange={(v) => set({ notifyCritical: v })} />
            <Toggle label="Case updates" desc="Notify when a case assigned to you changes." checked={prefs.notifyCase} onChange={(v) => set({ notifyCase: v })} />
            <Toggle label="Daily digest" checked={prefs.notifyDigest} onChange={(v) => set({ notifyDigest: v })} />
            <p className="py-3 text-[11px] text-sx-mute">Delivery (email / chat) requires a backend. These switches only save your preference.</p>
          </>)}
          {active === 'integrations' && (
            <div className="space-y-3 py-4 text-xs">
              <div className="flex justify-between"><span className="text-sx-mute">Backend API</span><span className="mono">{isBackendConfigured ? API_BASE_URL : 'Not configured (demo mode)'}</span></div>
              <p className="text-sx-mute">Per-tool configuration is on the Integrations page. API keys and passwords are never entered or stored in the browser.</p>
            </div>
          )}
          {active === 'retention' && (
            <div className="py-4">
              <Field label="Alert & case retention"><Select label="Retention" className="w-48" value={prefs.retention} onChange={(v) => set({ retention: v })} options={[{ value: '30', label: '30 days' }, { value: '90', label: '90 days' }, { value: '180', label: '180 days' }, { value: '365', label: '1 year' }]} /></Field>
              <p className="mt-3 text-[11px] text-sx-mute">Applied by the backend once connected. In the prototype this saves a preference only.</p>
              <button className="btn mt-4 text-sx-warn" onClick={() => { toast('Resetting demo data…', 'info'); resetAllDemoData(); }}>Reset local demo data</button>
            </div>
          )}
          {active === 'security' && (
            <ul className="list-disc space-y-2 py-4 pl-4 text-xs marker:text-sx-gold">
              <li>No authentication is implemented in this frontend prototype.</li>
              <li>Production needs server-side login (SSO/MFA), role-based access and HttpOnly session cookies.</li>
              <li>Secrets belong in a backend secrets store — never in <span className="mono">VITE_*</span> variables or local storage.</li>
              <li>Disruptive response actions need explicit, logged approval.</li>
            </ul>
          )}
          {active === 'about' && (
            <dl className="space-y-2 py-4 text-xs">
              <div className="flex justify-between"><dt className="text-sx-mute">Product</dt><dd>SentinelX — AI Security Operations Center</dd></div>
              <div className="flex justify-between"><dt className="text-sx-mute">Version</dt><dd className="mono">{APP_VERSION}</dd></div>
              <div className="flex justify-between"><dt className="text-sx-mute">Environment</dt><dd>{ENVIRONMENT_LABEL}</dd></div>
              <div className="flex justify-between"><dt className="text-sx-mute">Data source</dt><dd>{isBackendConfigured ? 'Backend API' : 'Local demo data'}</dd></div>
              <p className="pt-2 text-sx-mute">Frontend prototype. Live monitoring, AI analysis and external integrations are not operational until connected and tested.</p>
            </dl>
          )}
        </Panel>
      </div>
    </>
  );
}
