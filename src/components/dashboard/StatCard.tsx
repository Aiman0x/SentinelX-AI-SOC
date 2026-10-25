import type { LucideIcon } from 'lucide-react';
import { Area, AreaChart, ResponsiveContainer } from 'recharts';

interface Props {
  label: string;
  value: number | string;
  caption: string;
  icon: LucideIcon;
  accent?: 'red' | 'gold' | 'neutral';
  /** Small visual indicator series (sample data unless stated). */
  spark?: number[];
  isDemo?: boolean;
}

const accents = {
  red: { text: 'text-sx-red', hex: '#E53935', ring: 'border-sx-red/30 bg-sx-red/10' },
  gold: { text: 'text-sx-gold', hex: '#D4AF37', ring: 'border-sx-gold/30 bg-sx-gold/10' },
  neutral: { text: 'text-sx-ink', hex: '#8a8a8a', ring: 'border-sx-line bg-sx-elev' },
};

export function StatCard({ label, value, caption, icon: Icon, accent = 'neutral', spark, isDemo }: Props) {
  const a = accents[accent];
  const data = (spark ?? []).map((v, i) => ({ i, v }));
  return (
    <div className="panel relative overflow-hidden p-4">
      <div className="flex items-start justify-between">
        <div>
          <div className="text-[11px] font-medium uppercase tracking-wider text-sx-mute">{label}</div>
          <div className={`mt-1.5 text-3xl font-semibold tabular-nums ${accent === 'red' ? 'text-sx-ink' : ''}`}>{value}</div>
        </div>
        <div className={`flex h-9 w-9 items-center justify-center rounded-lg border ${a.ring}`}>
          <Icon className={`h-[18px] w-[18px] ${a.text}`} aria-hidden />
        </div>
      </div>
      <div className="mt-1 flex items-center justify-between text-[11px] text-sx-mute">
        <span>{caption}</span>
        {isDemo && <span className="text-[9px] font-semibold tracking-wider text-sx-gold/80">SAMPLE</span>}
      </div>
      {data.length > 0 && (
        <div className="mt-2 h-8" aria-hidden>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 2, bottom: 0, left: 0, right: 0 }}>
              <defs>
                <linearGradient id={`g-${label}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={a.hex} stopOpacity={0.35} />
                  <stop offset="100%" stopColor={a.hex} stopOpacity={0} />
                </linearGradient>
              </defs>
              <Area type="monotone" dataKey="v" stroke={a.hex} strokeWidth={1.5} fill={`url(#g-${label})`} isAnimationActive={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
      {accent === 'red' && <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-sx-red/70 to-transparent" aria-hidden />}
    </div>
  );
}
