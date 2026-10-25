import { X } from 'lucide-react';
import { useEffect, useId, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

interface Props {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  size?: 'sm' | 'md' | 'lg';
}

const widths = { sm: 'max-w-md', md: 'max-w-xl', lg: 'max-w-3xl' };

export function Modal({ open, onClose, title, children, size = 'md' }: Props) {
  const titleId = useId();
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/70 p-4 backdrop-blur-sm sm:items-center" onMouseDown={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className={`anim-fade panel w-full ${widths[size]} bg-sx-panel`}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="panel-header">
          <h2 id={titleId} className="panel-title">{title}</h2>
          <button className="btn btn-ghost btn-sm" onClick={onClose} aria-label="Close dialog"><X className="h-4 w-4" /></button>
        </div>
        <div className="p-4">{children}</div>
      </div>
    </div>,
    document.body,
  );
}
