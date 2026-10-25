import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';

export type ToastTone = 'info' | 'success' | 'warn' | 'error';
interface Toast {
  id: number;
  message: string;
  tone: ToastTone;
}

interface AppState {
  collapsed: boolean;
  toggleSidebar: () => void;
  mobileNavOpen: boolean;
  setMobileNavOpen: (v: boolean) => void;
  refreshKey: number;
  refresh: () => void;
  toasts: Toast[];
  toast: (message: string, tone?: ToastTone) => void;
  dismissToast: (id: number) => void;
  alertDrawerId: string | null;
  openAlert: (id: string) => void;
  closeAlert: () => void;
  analyst: string;
}

const Ctx = createContext<AppState | null>(null);

const COLLAPSE_KEY = 'sentinelx.ui.collapsed';
let toastId = 0;

export function AppProvider({ children }: { children: ReactNode }) {
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try {
      return window.localStorage.getItem(COLLAPSE_KEY) === '1';
    } catch {
      return false;
    }
  });
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [alertDrawerId, setAlertDrawerId] = useState<string | null>(null);

  const toggleSidebar = useCallback(() => {
    setCollapsed((c) => {
      try {
        window.localStorage.setItem(COLLAPSE_KEY, c ? '0' : '1');
      } catch {
        /* ignore */
      }
      return !c;
    });
  }, []);

  const dismissToast = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const toast = useCallback(
    (message: string, tone: ToastTone = 'info') => {
      const id = ++toastId;
      setToasts((t) => [...t.slice(-3), { id, message, tone }]);
      window.setTimeout(() => dismissToast(id), 5000);
    },
    [dismissToast],
  );

  const value = useMemo<AppState>(
    () => ({
      collapsed,
      toggleSidebar,
      mobileNavOpen,
      setMobileNavOpen,
      refreshKey,
      refresh: () => setRefreshKey((k) => k + 1),
      toasts,
      toast,
      dismissToast,
      alertDrawerId,
      openAlert: setAlertDrawerId,
      closeAlert: () => setAlertDrawerId(null),
      analyst: 'Aiman',
    }),
    [collapsed, toggleSidebar, mobileNavOpen, refreshKey, toasts, toast, dismissToast, alertDrawerId],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useApp(): AppState {
  const v = useContext(Ctx);
  if (!v) throw new Error('useApp must be used inside <AppProvider>');
  return v;
}
