import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { apiGet, apiPost, isDemoMode } from '../services/apiClient';

type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated';
interface AuthState {
  status: AuthStatus;
  login: (password: string) => Promise<void>;
  logout: () => Promise<void>;
}
const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>(isDemoMode ? 'authenticated' : 'loading');

  useEffect(() => {
    if (isDemoMode) return;
    let active = true;
    apiGet<{ authenticated: boolean }>('/api/auth/me')
      .then((result) => { if (active) setStatus(result.authenticated ? 'authenticated' : 'unauthenticated'); })
      .catch(() => { if (active) setStatus('unauthenticated'); });
    return () => { active = false; };
  }, []);

  const login = useCallback(async (password: string) => {
    await apiPost<{ authenticated: boolean }>('/api/auth/login', { password });
    setStatus('authenticated');
  }, []);

  const logout = useCallback(async () => {
    try { await apiPost<{ authenticated: boolean }>('/api/auth/logout', {}); }
    finally { setStatus('unauthenticated'); }
  }, []);

  const value = useMemo(() => ({ status, login, logout }), [status, login, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used inside AuthProvider');
  return value;
}
