const pad = (n: number) => String(n).padStart(2, '0');

export function formatDateTime(iso?: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function formatTime(iso?: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function timeAgo(iso?: string): string {
  if (!iso) return 'never';
  const diff = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(diff)) return '—';
  const m = Math.round(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

/** Helper used by demo data: ISO timestamp N minutes before "now". */
export function minutesAgo(min: number): string {
  return new Date(Date.now() - min * 60000).toISOString();
}
