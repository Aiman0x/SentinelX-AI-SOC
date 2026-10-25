import type { ReactNode } from 'react';
import { DemoTag } from '../common/StatusBadge';
import { isDemoMode } from '../../services/apiClient';

interface Props {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  /** Show the DEMO DATA tag next to the title (auto-hidden when a backend is configured). */
  demo?: boolean;
}

export function PageHeader({ title, subtitle, actions, demo = true }: Props) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <div className="flex items-center gap-2.5">
          <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
          {demo && isDemoMode && <DemoTag />}
        </div>
        {subtitle && <p className="mt-1 text-xs text-sx-mute">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
