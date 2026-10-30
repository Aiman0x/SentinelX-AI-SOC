import { useState, type FormEvent } from 'react';
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
import { isDemoMode } from './services/apiClient';

function LoginScreen() {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

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
    <main className="flex min-h-full items-center justify-center px-4 py-10">
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
      </form>
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
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}

export default function App() {
  return <AuthenticatedApp />;
}
