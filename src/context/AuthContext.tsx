import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { apiGet, apiPost, isDemoMode } from '../services/apiClient';

type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated';
type AuthUser = { id: string; email: string; name?: string; display_name?: string; role?: string; organization_id?: string };
interface AuthState {
  status: AuthStatus;
  user: AuthUser | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}
const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>(isDemoMode ? 'authenticated' : 'loading');
  const [user, setUser] = useState<AuthUser | null>(null);

  useEffect(() => {
    if (isDemoMode) return;
    let active = true;
    apiGet<{ authenticated: boolean; user?: AuthUser }>('/api/auth/me')
      .then((result) => {
        if (!active) return;
        setStatus(result.authenticated ? 'authenticated' : 'unauthenticated');
        setUser(result.authenticated && result.user ? result.user : null);
      })
      .catch(() => { if (active) { setStatus('unauthenticated'); setUser(null); } });
    return () => { active = false; };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const result = await apiPost<{ authenticated: boolean; user?: AuthUser }>('/api/auth/login', { email, password });
    setUser(result.user ?? null);
    setStatus('authenticated');
  }, []);

  const logout = useCallback(async () => {
    try { await apiPost<{ authenticated: boolean }>('/api/auth/logout', {}); }
    finally { setUser(null); setStatus('unauthenticated'); }
  }, []);

  const value = useMemo(() => ({ status, user, login, logout }), [status, user, login, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used inside AuthProvider');
  return value;
}
