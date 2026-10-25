import { AlertTriangle, Inbox, Loader2, PlugZap } from 'lucide-react';
import type { ReactNode } from 'react';

interface Props {
  title: string;
  description?: string;
  icon?: ReactNode;
  action?: ReactNode;
}

export function EmptyState({ title, description, icon, action }: Props) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      <div className="text-sx-mute">{icon ?? <Inbox className="h-8 w-8" />}</div>
      <div className="text-sm font-medium text-sx-ink">{title}</div>
      {description && <p className="max-w-sm text-xs text-sx-mute">{description}</p>}
      {action}
    </div>
  );
}

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 px-6 py-12 text-xs text-sx-mute" role="status">
      <Loader2 className="h-4 w-4 animate-spin text-sx-gold" /> {label}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <EmptyState
      icon={<AlertTriangle className="h-8 w-8 text-sx-red" />}
      title="Something went wrong"
      description={message}
      action={onRetry && <button className="btn mt-2" onClick={onRetry}>Retry</button>}
    />
  );
}

export function DisconnectedState({ name }: { name: string }) {
  return (
    <EmptyState
      icon={<PlugZap className="h-8 w-8 text-sx-warn" />}
      title={`${name} is not connected`}
      description="Configure the integration and run a successful health check to see live data here."
    />
  );
}
