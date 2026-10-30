import { useState } from 'react';
import { Area, AreaChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { TrendRange } from '../../data/demoTrends';
import { useData } from '../../hooks/useData';
import { loadTrend } from '../../services/miscService';
import { SEVERITIES, cap, severityHex } from '../../utils/severity';
import { Segmented, Panel } from '../common/Controls';
import { ErrorState, LoadingState } from '../common/EmptyState';
import { DemoTag } from '../common/StatusBadge';

export function SecurityTrendChart() {
  const [range, setRange] = useState<TrendRange>('24h');
  const { data, loading, error, reload } = useData(() => loadTrend(range), [range]);

  return (
    <Panel
      title={<span className="flex items-center gap-2">Security Events Over Time <DemoTag /></span>}
      right={
        <Segmented<TrendRange> label="Time range" value={range} onChange={setRange}
          options={[{ value: '24h', label: '24 hours' }, { value: '7d', label: '7 days' }, { value: '30d', label: '30 days' }]} />
      }
      bodyClass="p-4"
    >
      {loading && !data ? <LoadingState /> : error ? <ErrorState message={error} onRetry={reload} /> : (
        <>
        <p className="mb-2 text-[10px] text-sx-mute">Illustrative sample trend only. Live event aggregation is not connected yet.</p>
        <div className="h-72" role="img" aria-label={`Stacked area chart of alerts by severity over the last ${range}. Sample data.`}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data ?? []} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
              <defs>
                {SEVERITIES.map((s) => (
                  <linearGradient key={s} id={`tg-${s}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={severityHex[s]} stopOpacity={0.45} />
                    <stop offset="100%" stopColor={severityHex[s]} stopOpacity={0.02} />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid stroke="#222" vertical={false} />
              <XAxis dataKey="label" tick={{ fill: '#969696', fontSize: 11 }} tickLine={false} axisLine={{ stroke: '#292929' }} interval="preserveStartEnd" minTickGap={24} />
              <YAxis tick={{ fill: '#969696', fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip contentStyle={{ background: '#1B1B1B', border: '1px solid #292929', borderRadius: 8, fontSize: 12 }} labelStyle={{ color: '#F3F3F3' }} cursor={{ stroke: '#444' }} />
              <Legend iconType="circle" wrapperStyle={{ fontSize: 11, color: '#969696' }} formatter={(v: string) => cap(v)} />
              {[...SEVERITIES].reverse().map((s) => (
                <Area key={s} type="monotone" dataKey={s} stackId="1" stroke={severityHex[s]} strokeWidth={1.5} fill={`url(#tg-${s})`} isAnimationActive={false} />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>
        </>
      )}
    </Panel>
  );
}
