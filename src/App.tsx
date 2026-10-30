import { useEffect, useState, type FormEvent } from 'react';
import { Route, Routes } from 'react-router-dom';
import { AppLayout } from './components/layout/AppLayout';
import { useAuth } from './context/AuthContext';
import Alerts from './pages/Alerts';
import Assets from './pages/Assets';
import AuditLogs from './pages/AuditLogs';
import Cases from './pages/Cases';
import DetectionRules from './pages/DetectionRules';
import Integrations from './pages/Integrations';
import Investigation from './pages/Investigation';
import NotFound from './pages/NotFound';
import Overview from './pages/Overview';
import Playbooks from './pages/Playbooks';
import Settings from './pages/Settings';
import Users from './pages/Users';
import { API_BASE_URL, apiGet, isDemoMode } from './services/apiClient';

function LoginScreen() {
  const { login } = useAuth();
  const [email, setEmail] = useState('aiman132046@gmail.com');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [bootstrapAvailable, setBootstrapAvailable] = useState(false);
  const [setupMode, setSetupMode] = useState(false);
  const [setupSecret, setSetupSecret] = useState('');
  const [setupName, setSetupName] = useState('Aiman Salman');
  const [setupPassword, setSetupPassword] = useState('');
  const [setupConfirm, setSetupConfirm] = useState('');
  const [setupBusy, setSetupBusy] = useState(false);
  const [setupError, setSetupError] = useState('');
  const [setupNotice, setSetupNotice] = useState('');

  useEffect(() => {
    apiGet<{ bootstrapAvailable: boolean }>('/api/auth/bootstrap-status')
      .then(result => setBootstrapAvailable(result.bootstrapAvailable))
      .catch(() => setBootstrapAvailable(false));
  }, []);

  const initializeAdmin = async (event: FormEvent) => {
    event.preventDefault(); setSetupError(''); setSetupNotice('');
    if (setupPassword !== setupConfirm) { setSetupError('Passwords do not match.'); return; }
    // HTTP header values must be byte-safe ASCII. Trim copied whitespace and reject hidden/non-ASCII characters.
    const normalizedBootstrapSecret = setupSecret.trim();
    if (!/^[\x20-\x7E]+$/.test(normalizedBootstrapSecret)) {
      setSetupError('Bootstrap secret contains unsupported characters. Copy the original Cloudflare secret again; do not type or translate it.');
      return;
    }
    setSetupBusy(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/bootstrap`, {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'X-SentinelX-Bootstrap': normalizedBootstrapSecret },
        body: JSON.stringify({ email, name: setupName, password: setupPassword, organization: 'SentinelX' }),
      });
      const contentType = response.headers.get('content-type') || '';
      const rawResponse = await response.text();
      let payload: { error?: string } = {};
      if (contentType.includes('application/json')) {
        try { payload = JSON.parse(rawResponse) as { error?: string }; }
        catch { throw new Error(`Backend returned malformed JSON (HTTP ${response.status}).`); }
      } else {
        throw new Error(`Backend returned a non-JSON response (HTTP ${response.status}, ${contentType || 'unknown content type'}). The frontend may be using an outdated API route.`);
      }
      if (!response.ok) throw new Error(payload.error || `Admin setup failed (HTTP ${response.status}).`);
      setBootstrapAvailable(false); setSetupMode(false); setPassword('');
      setSetupSecret(''); setSetupPassword(''); setSetupConfirm('');
      setSetupNotice('Initial Admin account created. Sign in with your new password.');
    } catch (e) { setSetupError(e instanceof Error ? e.message : 'Could not initialize administrator.'); }
    finally { setSetupBusy(false); }
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError('');
    setBusy(true);
    try {
      await login(email, password);
      setPassword('');
    } catch {
      setError('Login failed. Check your password or try again later.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="flex min-h-full flex-col items-center justify-center gap-4 px-4 py-10">
      <form onSubmit={submit} className="panel w-full max-w-sm p-7">
        <div className="mb-6 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-sx-red/50 bg-sx-reddark/40 text-lg font-black text-sx-red">SX</div>
          <div>
            <h1 className="text-lg font-bold tracking-wide">SENTINEL<span className="text-sx-red">X</span></h1>
            <p className="text-[10px] uppercase tracking-[0.22em] text-sx-mute">Security Operations Center</p>
          </div>
        </div>
        <div className="mb-5 border-b border-sx-line pb-4">
          <p className="text-sm font-semibold">Analyst authentication</p>
          <p className="mt-1 text-xs text-sx-mute">Sign in to access the SentinelX security console.</p>
        </div>
        <label htmlFor="analyst-email" className="label">Work email</label>
        <input id="analyst-email" type="email" autoComplete="username" required maxLength={254} value={email} onChange={(event) => setEmail(event.target.value)} className="input mb-4 py-2.5" placeholder="analyst@company.com" />
        <label htmlFor="analyst-password" className="label">Password</label>
        <input
          id="analyst-password"
          type="password"
          autoComplete="current-password"
          required
          maxLength={256}
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          className="input py-2.5"
          placeholder="Enter your analyst password"
        />
        {error && <p role="alert" className="mt-3 text-xs text-sx-red">{error}</p>}
        <button type="submit" disabled={busy || !email || !password} className="btn btn-primary mt-5 w-full py-2.5">
          {busy ? 'Authenticating…' : 'Secure sign in'}
        </button>
        <p className="mt-4 text-center text-[10px] text-sx-mute">Session expires automatically after four hours.</p>
        {setupNotice && <p role="status" className="mt-3 text-center text-xs text-sx-gold">{setupNotice}</p>}
        {bootstrapAvailable && <button type="button" className="mt-4 w-full border-t border-sx-line pt-4 text-xs text-sx-gold hover:text-white" onClick={() => { setSetupMode(v=>!v); setSetupError(''); }}>{setupMode ? 'Back to sign in' : 'Initialize first Admin account'}</button>}
      </form>
      {setupMode && bootstrapAvailable && (
        <form onSubmit={initializeAdmin} className="panel mt-4 w-full max-w-sm space-y-3 p-6">
          <h2 className="text-sm font-semibold">Secure first-time setup</h2>
          <p className="text-[11px] text-sx-mute">Enter the one-time bootstrap secret configured in Cloudflare Worker secrets. This value is sent only to your SentinelX backend over HTTPS.</p>
          <label className="block"><span className="label">Bootstrap secret</span><input className="input" type="password" autoComplete="off" required value={setupSecret} onChange={e=>setSetupSecret(e.target.value)} /></label>
          <label className="block"><span className="label">Admin email</span><input className="input" type="email" required maxLength={254} value={email} onChange={e=>setEmail(e.target.value)} /></label>
          <label className="block"><span className="label">Display name</span><input className="input" required minLength={2} maxLength={100} value={setupName} onChange={e=>setSetupName(e.target.value)} /></label>
          <label className="block"><span className="label">New password</span><input className="input" type="password" autoComplete="new-password" required minLength={14} maxLength={256} value={setupPassword} onChange={e=>setSetupPassword(e.target.value)} /></label>
          <label className="block"><span className="label">Confirm password</span><input className="input" type="password" autoComplete="new-password" required minLength={14} maxLength={256} value={setupConfirm} onChange={e=>setSetupConfirm(e.target.value)} /></label>
          {setupError && <p role="alert" className="text-xs text-sx-red">{setupError}</p>}
          <button className="btn btn-primary w-full" type="submit" disabled={setupBusy || !setupSecret || setupPassword.length<14 || !setupName || !email}>{setupBusy?'Creating Admin…':'Create first Admin'}</button>
        </form>
      )}
    </main>
  );
}

function AuthenticatedApp() {
  const { status } = useAuth();
  if (isDemoMode) {
    return (
      <Routes>
        <Route element={<AppLayout />}>
          <Route index element={<Overview />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="cases" element={<Cases />} />
          <Route path="investigation" element={<Investigation />} />
          <Route path="assets" element={<Assets />} />
          <Route path="integrations" element={<Integrations />} />
          <Route path="rules" element={<DetectionRules />} />
          <Route path="playbooks" element={<Playbooks />} />
          <Route path="audit" element={<AuditLogs />} />
          <Route path="settings" element={<Settings />} />
          <Route path="users" element={<Users />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    );
  }
  if (status === 'loading') return <div className="flex min-h-full items-center justify-center text-xs text-sx-mute">Checking secure session…</div>;
  if (status !== 'authenticated') return <LoginScreen />;
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<Overview />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="cases" element={<Cases />} />
        <Route path="investigation" element={<Investigation />} />
        <Route path="assets" element={<Assets />} />
        <Route path="integrations" element={<Integrations />} />
        <Route path="rules" element={<DetectionRules />} />
        <Route path="playbooks" element={<Playbooks />} />
        <Route path="audit" element={<AuditLogs />} />
        <Route path="settings" element={<Settings />} />
        <Route path="users" element={<Users />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}

export default function App() {
  return <AuthenticatedApp />;
}
