import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { UserPlus, UserX, RefreshCw, ShieldCheck } from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { Panel } from '../components/common/Controls';
import { apiDelete, apiGet, apiPost } from '../services/apiClient';

type Role = 'owner' | 'admin' | 'analyst' | 'viewer';
interface Member {
  id: string;
  email: string;
  display_name: string;
  role: Role;
  is_active: number;
  created_at: string;
  last_login_at: string | null;
}
interface CurrentUser { id: string; role: Role; email: string; name?: string; display_name?: string; }

export default function Users() {
  const [members, setMembers] = useState<Member[]>([]);
  const [actor, setActor] = useState<CurrentUser | null>(null);
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<'admin' | 'analyst' | 'viewer'>('analyst');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [result, session] = await Promise.all([
        apiGet<{ users: Member[] }>('/api/admin/users'),
        apiGet<{ authenticated: boolean; user: CurrentUser }>('/api/auth/me'),
      ]);
      setMembers(result.users || []);
      setActor(session.user);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load organization users.');
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const create = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true); setError(''); setNotice('');
    try {
      await apiPost('/api/admin/users', { email, name, password, role });
      setEmail(''); setName(''); setPassword('');
      setNotice('User account created successfully.');
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not create user.');
    } finally { setSaving(false); }
  };

  const disable = async (member: Member) => {
    if (!window.confirm(`Disable ${member.email}? Their active sessions will be revoked.`)) return;
    setError(''); setNotice('');
    try {
      await apiDelete(`/api/admin/users/${member.id}`);
      setNotice(`${member.email} has been disabled.`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not disable user.');
    }
  };

  const canManage = actor?.role === 'owner' || actor?.role === 'admin';
  if (!loading && error && !members.length && !actor) {
    return <><PageHeader title="User Management" subtitle="Organization membership and role administration." /><Panel><div className="p-4 text-sm text-sx-warn">{error}. This area requires an authenticated organization Admin or Owner account.</div></Panel></>;
  }

  return (
    <>
      <PageHeader title="User Management" subtitle="Create and manage accounts within your SentinelX organization." actions={<button className="btn btn-ghost" onClick={() => void load()}><RefreshCw className="mr-2 h-3.5 w-3.5" />Refresh</button>} />
      {error && <div role="alert" className="mb-4 rounded-lg border border-sx-red/30 bg-sx-reddark/20 p-3 text-xs text-sx-red">{error}</div>}
      {notice && <div role="status" className="mb-4 rounded-lg border border-sx-gold/30 bg-sx-gold/5 p-3 text-xs text-sx-gold">{notice}</div>}
      {!canManage && actor && <div className="mb-4 rounded-lg border border-sx-red/30 bg-sx-reddark/20 p-3 text-xs text-sx-red">Admin or Owner permission is required to manage users.</div>}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.5fr)]">
        <Panel title="Create organization user">
          <form onSubmit={create} className="space-y-3 p-4">
            <label className="block"><span className="label">Full name</span><input className="input" required minLength={2} maxLength={100} value={name} onChange={e=>setName(e.target.value)} placeholder="Analyst name" /></label>
            <label className="block"><span className="label">Work email</span><input className="input" type="email" required maxLength={254} value={email} onChange={e=>setEmail(e.target.value)} placeholder="analyst@company.com" /></label>
            <label className="block"><span className="label">Temporary password</span><input className="input" type="password" required minLength={14} maxLength={256} autoComplete="new-password" value={password} onChange={e=>setPassword(e.target.value)} placeholder="At least 14 characters" /><span className="mt-1 block text-[10px] text-sx-mute">Share this securely with the new user. Never reuse your own password.</span></label>
            <label className="block"><span className="label">Role</span><select className="input" value={role} onChange={e=>setRole(e.target.value as typeof role)}><option value="analyst">Analyst</option><option value="viewer">Viewer</option>{actor?.role==='owner' && <option value="admin">Admin</option>}</select></label>
            <button className="btn btn-primary w-full" type="submit" disabled={!canManage || saving || password.length<14}><UserPlus className="mr-2 h-4 w-4" />{saving?'Creating…':'Create user'}</button>
            {actor?.role==='admin' && <p className="text-[10px] text-sx-mute">Only the organization Owner can create another Admin.</p>}
          </form>
        </Panel>
        <Panel title={`Organization members · ${members.length}`} right={<span className="text-[10px] text-sx-mute">Owner / Admin / Analyst / Viewer</span>}>
          {loading ? <div className="p-5 text-xs text-sx-mute">Loading members…</div> : members.length===0 ? <div className="p-5 text-xs text-sx-mute">No organization members found.</div> : (
            <div className="overflow-x-auto"><table className="w-full text-left text-xs"><thead><tr className="border-b border-sx-line text-[10px] uppercase tracking-wider text-sx-mute"><th className="px-4 py-3">Member</th><th className="px-3 py-3">Role</th><th className="px-3 py-3">Status</th><th className="px-3 py-3">Last login</th><th className="px-3 py-3">Action</th></tr></thead><tbody>{members.map(m=><tr key={m.id} className="border-b border-sx-line/70"><td className="px-4 py-3"><div className="font-medium">{m.display_name}</div><div className="mt-0.5 text-[10px] text-sx-mute">{m.email}</div></td><td className="px-3 py-3"><span className="inline-flex items-center gap-1 rounded border border-sx-gold/20 px-2 py-1 text-[10px] text-sx-gold">{m.role==='owner'&&<ShieldCheck className="h-3 w-3" />}{m.role}</span></td><td className="px-3 py-3">{m.is_active===1?'Active':'Disabled'}</td><td className="px-3 py-3 text-sx-mute">{m.last_login_at?new Date(m.last_login_at).toLocaleString():'Never'}</td><td className="px-3 py-3">{m.role!=='owner' && m.id!==actor?.id && m.is_active===1 && <button className="btn btn-ghost btn-sm text-sx-red" disabled={!canManage} onClick={()=>void disable(m)} title="Disable user"><UserX className="h-3.5 w-3.5" /></button>}</td></tr>)}</tbody></table></div>
          )}
        </Panel>
      </div>
    </>
  );
}
