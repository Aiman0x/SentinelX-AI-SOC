import { CheckCircle2, Info, TriangleAlert, XCircle, X } from 'lucide-react';
import { useApp } from '../../context/AppContext';

const icons = {
  info: <Info className="h-4 w-4 text-sx-gold" />,
  success: <CheckCircle2 className="h-4 w-4 text-sx-ok" />,
  warn: <TriangleAlert className="h-4 w-4 text-sx-warn" />,
  error: <XCircle className="h-4 w-4 text-sx-red" />,
};

export function Toasts() {
  const { toasts, dismissToast } = useApp();
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[min(380px,calc(100vw-2rem))] flex-col gap-2" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className="anim-fade pointer-events-auto flex items-start gap-2.5 rounded-lg border border-sx-line bg-sx-elev px-3 py-2.5 text-xs shadow-2xl">
          <span className="mt-0.5">{icons[t.tone]}</span>
          <span className="flex-1">{t.message}</span>
          <button onClick={() => dismissToast(t.id)} className="text-sx-mute hover:text-sx-ink" aria-label="Dismiss"><X className="h-3.5 w-3.5" /></button>
        </div>
      ))}
    </div>
  );
}
