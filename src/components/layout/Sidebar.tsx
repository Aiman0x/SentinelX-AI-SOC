import { PanelLeftClose, PanelLeftOpen } from 'lucide-react';
import { NavLink } from 'react-router-dom';
import { useApp } from '../../context/AppContext';
import { ENVIRONMENT_LABEL, isDemoMode } from '../../services/apiClient';
import { navItems } from './nav';

export const APP_VERSION = 'v0.1.0';

export function Sidebar() {
  const { collapsed, toggleSidebar, mobileNavOpen, setMobileNavOpen } = useApp();

  return (
    <>
      {mobileNavOpen && <div className="fixed inset-0 z-30 bg-black/60 lg:hidden" onClick={() => setMobileNavOpen(false)} aria-hidden />}
      <aside
        aria-label="Primary"
        className={`fixed inset-y-0 left-0 z-40 flex flex-col border-r border-sx-line bg-sx-side transition-[width,transform] duration-200 lg:static lg:translate-x-0
          ${mobileNavOpen ? 'translate-x-0' : '-translate-x-full'} ${collapsed ? 'lg:w-[68px]' : 'lg:w-64'} w-64`}
      >
        {/* Brand */}
        <div className={`flex h-14 items-center gap-3 border-b border-sx-line ${collapsed ? 'lg:justify-center lg:px-0' : ''} px-4`}>
          <img src="/logo.svg" alt="" className="h-8 w-8 shrink-0" />
          <div className={`min-w-0 leading-tight ${collapsed ? 'lg:hidden' : ''}`}>
            <div className="text-[15px] font-bold tracking-[0.18em] text-sx-ink">SENTINEL<span className="text-sx-red">X</span></div>
            <div className="whitespace-nowrap text-[9px] uppercase tracking-[0.08em] text-sx-gold/80">AI Security Operations Center</div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 space-y-0.5 overflow-y-auto px-2 py-3">
          {navItems.filter(({ to }) => (to !== '/users' || !isDemoMode) && (to !== '/telemetry' || !isDemoMode)).map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              title={collapsed ? label : undefined}
              onClick={() => setMobileNavOpen(false)}
              className={({ isActive }) =>
                `group relative flex items-center gap-3 rounded-lg px-3 py-2 text-[13px] transition-colors ${collapsed ? 'lg:justify-center lg:px-0' : ''}
                ${isActive ? 'bg-sx-reddark/25 font-medium text-sx-ink' : 'text-sx-mute hover:bg-sx-elev hover:text-sx-ink'}`
              }
            >
              {({ isActive }) => (
                <>
                  {isActive && <span className="absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-r bg-sx-red shadow-[0_0_8px_#E53935]" aria-hidden />}
                  <Icon className={`h-[18px] w-[18px] shrink-0 ${isActive ? 'text-sx-gold' : ''}`} aria-hidden />
                  <span className={collapsed ? 'lg:sr-only' : ''}>{label}</span>
                </>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="border-t border-sx-line p-3">
          <button
            onClick={toggleSidebar}
            className={`btn btn-ghost mb-2 hidden w-full lg:inline-flex ${collapsed ? '' : 'justify-start'}`}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <PanelLeftOpen className="h-4 w-4" /> : <><PanelLeftClose className="h-4 w-4" /> Collapse</>}
          </button>
          <div className={`rounded-lg border border-sx-gold/30 bg-sx-gold/5 px-2.5 py-1.5 text-center ${collapsed ? 'lg:px-0' : ''}`}>
            <div className={`text-[10px] font-semibold tracking-wider text-sx-gold ${collapsed ? 'lg:hidden' : ''}`}>{ENVIRONMENT_LABEL}</div>
            <div className="mono text-[10px] text-sx-mute">{APP_VERSION}</div>
          </div>
        </div>
      </aside>
    </>
  );
}
