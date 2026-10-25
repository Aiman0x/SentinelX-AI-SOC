/** DEMO DATA — deterministic synthetic series for the overview chart. Not real telemetry. */
export type TrendRange = '24h' | '7d' | '30d';

export interface TrendPoint {
  label: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

// Small deterministic pseudo-random generator so the chart looks the same on every load.
function rng(seed: number) {
  let s = seed;
  return () => {
    s = (s * 1664525 + 1013904223) % 4294967296;
    return s / 4294967296;
  };
}

export function buildTrend(range: TrendRange): TrendPoint[] {
  const r = rng(range === '24h' ? 11 : range === '7d' ? 29 : 47);
  const count = range === '24h' ? 24 : range === '7d' ? 7 : 30;
  const now = new Date();
  const pts: TrendPoint[] = [];
  for (let i = count - 1; i >= 0; i--) {
    const d = new Date(now);
    let label: string;
    if (range === '24h') {
      d.setHours(now.getHours() - i);
      label = `${String(d.getHours()).padStart(2, '0')}:00`;
    } else {
      d.setDate(now.getDate() - i);
      label = d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
    }
    const k = range === '24h' ? 1 : range === '7d' ? 7 : 5;
    pts.push({
      label,
      critical: Math.round(r() * 1.6 * (k > 1 ? 2 : 1)),
      high: Math.round((1 + r() * 3) * k * 0.6),
      medium: Math.round((2 + r() * 5) * k * 0.6),
      low: Math.round((3 + r() * 6) * k * 0.6),
    });
  }
  return pts;
}
