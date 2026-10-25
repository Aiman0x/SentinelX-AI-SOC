import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';
import type { Alert } from '../../types/alert';
import { SEVERITIES, cap, severityHex } from '../../utils/severity';
import { Panel } from '../common/Controls';
import { DemoTag } from '../common/StatusBadge';
import { isDemoMode } from '../../services/apiClient';

export function SeverityChart({ alerts }: { alerts: Alert[] }) {
  const data = SEVERITIES.map((s) => ({ name: cap(s), key: s, value: alerts.filter((a) => a.severity === s).length }));
  const total = data.reduce((n, d) => n + d.value, 0);

  return (
    <Panel title={<span className="flex items-center gap-2">Alert Severity Distribution {isDemoMode && <DemoTag />}</span>} bodyClass="p-4">
      <div className="relative mx-auto h-48 w-48" role="img" aria-label={`Donut chart of ${total} alerts by severity`}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} dataKey="value" innerRadius={58} outerRadius={84} paddingAngle={3} stroke="#141414" strokeWidth={2} isAnimationActive={false}>
              {data.map((d) => <Cell key={d.key} fill={severityHex[d.key]} />)}
            </Pie>
            <Tooltip contentStyle={{ background: '#1B1B1B', border: '1px solid #292929', borderRadius: 8, fontSize: 12 }} itemStyle={{ color: '#F3F3F3' }} />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <div className="text-2xl font-semibold tabular-nums">{total}</div>
          <div className="text-[10px] uppercase tracking-wider text-sx-mute">Alerts</div>
        </div>
      </div>
      <ul className="mt-4 space-y-1.5 text-xs">
        {data.map((d) => (
          <li key={d.key} className="flex items-center justify-between">
            <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: severityHex[d.key] }} aria-hidden />{d.name}</span>
            <span className="tabular-nums text-sx-mute">{d.value} <span className="text-[10px]">({total ? Math.round((d.value / total) * 100) : 0}%)</span></span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
