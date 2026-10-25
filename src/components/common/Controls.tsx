import { ChevronDown, ChevronLeft, ChevronRight, ChevronsUpDown, ChevronUp } from 'lucide-react';
import type { ReactNode } from 'react';

/** Styled native <select> with a visible label (accessible). */
export function Select({
  label, value, onChange, options, className = '',
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  className?: string;
}) {
  return (
    <label className={`block ${className}`}>
      <span className="sr-only">{label}</span>
      <div className="relative">
        <select className="input appearance-none pr-7" value={value} onChange={(e) => onChange(e.target.value)} aria-label={label}>
          {options.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
        <ChevronDown className="pointer-events-none absolute right-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-sx-mute" aria-hidden />
      </div>
    </label>
  );
}

export function Segmented<T extends string>({
  value, onChange, options, label,
}: {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: string }[];
  label: string;
}) {
  return (
    <div role="group" aria-label={label} className="inline-flex rounded-lg border border-sx-line bg-sx-bg p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          aria-pressed={value === o.value}
          onClick={() => onChange(o.value)}
          className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors ${value === o.value ? 'bg-sx-elev text-sx-gold' : 'text-sx-mute hover:text-sx-ink'}`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function SortHeader({
  label, active, dir, onClick,
}: {
  label: string;
  active: boolean;
  dir: 'asc' | 'desc';
  onClick: () => void;
}) {
  const Icon = !active ? ChevronsUpDown : dir === 'asc' ? ChevronUp : ChevronDown;
  return (
    <th className="th" aria-sort={active ? (dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button className={`inline-flex items-center gap-1 uppercase tracking-wider hover:text-sx-ink ${active ? 'text-sx-gold' : ''}`} onClick={onClick}>
        {label}
        <Icon className="h-3 w-3" aria-hidden />
      </button>
    </th>
  );
}

export function Pagination({
  page, pageSize, total, onPage,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (p: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <div className="flex items-center justify-between border-t border-sx-line px-4 py-2.5 text-xs text-sx-mute">
      <span>{from}–{to} of {total}</span>
      <div className="flex items-center gap-1">
        <button className="btn btn-sm" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page"><ChevronLeft className="h-3.5 w-3.5" /></button>
        <span className="px-2">Page {page} / {pages}</span>
        <button className="btn btn-sm" disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page"><ChevronRight className="h-3.5 w-3.5" /></button>
      </div>
    </div>
  );
}

export function Field({ label, children, htmlFor }: { label: string; children: ReactNode; htmlFor?: string }) {
  return (
    <div>
      <label className="label" htmlFor={htmlFor}>{label}</label>
      {children}
    </div>
  );
}

export function Panel({ title, right, children, className = '', bodyClass = '' }: { title?: ReactNode; right?: ReactNode; children: ReactNode; className?: string; bodyClass?: string }) {
  return (
    <section className={`panel ${className}`}>
      {(title || right) && (
        <div className="panel-header">
          <h2 className="panel-title">{title}</h2>
          {right}
        </div>
      )}
      <div className={bodyClass}>{children}</div>
    </section>
  );
}
