import { Outlet, useLocation } from 'react-router-dom';
import { useEffect, useRef } from 'react';
import { useApp } from '../../context/AppContext';
import { AlertDetails } from '../alerts/AlertDetails';
import { Toasts } from '../common/Toasts';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';
import { isDemoMode } from '../../services/apiClient';

export function AppLayout() {
  const { alertDrawerId, closeAlert } = useApp();
  const { pathname } = useLocation();
  const main = useRef<HTMLElement>(null);

  useEffect(() => {
    main.current?.scrollTo({ top: 0 });
  }, [pathname]);

  return (
    <div className="flex h-full">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-sx-gold focus:px-3 focus:py-1 focus:text-black">Skip to content</a>
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        {isDemoMode && (
          <div className="border-b border-sx-gold/20 bg-sx-gold/5 px-4 py-1 text-center text-[11px] text-sx-gold/90" role="note">
            DEMO MODE — all alerts, assets, cases and integration states are sample data. No live telemetry or external integration is connected.
          </div>
        )}
        <main id="main" ref={main} className="flex-1 overflow-y-auto p-4 lg:p-6">
          <div className="mx-auto max-w-[1500px] anim-fade" key={pathname}>
            <Outlet />
          </div>
        </main>
      </div>
      <AlertDetails alertId={alertDrawerId} onClose={closeAlert} />
      <Toasts />
    </div>
  );
}
