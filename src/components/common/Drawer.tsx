import { X } from 'lucide-react';
import { useEffect, useId, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

interface Props {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  subtitle?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  width?: string;
}

export function Drawer({ open, onClose, title, subtitle, children, footer, width = 'max-w-2xl' }: Props) {
  const id = useId();
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-40 flex justify-end bg-black/60 backdrop-blur-[2px]" onMouseDown={onClose}>
      <aside
        role="dialog"
        aria-modal="true"
        aria-labelledby={id}
        className={`anim-slide flex h-full w-full ${width} flex-col border-l border-sx-line bg-sx-side shadow-2xl`}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-3 border-b border-sx-line px-5 py-4">
          <div className="min-w-0">
            <h2 id={id} className="truncate text-sm font-semibold">{title}</h2>
            {subtitle && <div className="mt-1 text-xs text-sx-mute">{subtitle}</div>}
          </div>
          <button className="btn btn-ghost btn-sm" onClick={onClose} aria-label="Close panel"><X className="h-4 w-4" /></button>
        </div>
        <div className="flex-1 overflow-y-auto px-5 py-4">{children}</div>
        {footer && <div className="flex flex-wrap justify-end gap-2 border-t border-sx-line bg-sx-panel px-5 py-3">{footer}</div>}
      </aside>
    </div>,
    document.body,
  );
}
