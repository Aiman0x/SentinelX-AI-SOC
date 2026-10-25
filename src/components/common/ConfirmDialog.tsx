import { useEffect, useState } from 'react';
import { ShieldAlert } from 'lucide-react';
import { Modal } from './Modal';

interface Props {
  open: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  /** When set, the user must type this exact word to enable the confirm button (for disruptive actions). */
  requireTyped?: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({ open, title, message, confirmLabel = 'Confirm', requireTyped, danger, onConfirm, onCancel }: Props) {
  const [typed, setTyped] = useState('');
  useEffect(() => {
    if (open) setTyped('');
  }, [open]);
  const ok = !requireTyped || typed === requireTyped;

  return (
    <Modal open={open} onClose={onCancel} title={title} size="sm">
      <div className="space-y-3">
        <div className="flex gap-3">
          {danger && <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-sx-red" aria-hidden />}
          <p className="text-xs text-sx-mute">{message}</p>
        </div>
        {requireTyped && (
          <div>
            <label className="label" htmlFor="confirm-typed">
              Type <span className="mono text-sx-gold">{requireTyped}</span> to continue
            </label>
            <input id="confirm-typed" className="input mono" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
          </div>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <button className="btn" onClick={onCancel}>Cancel</button>
          <button className={`btn ${danger ? 'btn-primary' : 'btn-gold'}`} disabled={!ok} onClick={onConfirm}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </Modal>
  );
}
