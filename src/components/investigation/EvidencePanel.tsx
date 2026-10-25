import type { Alert } from '../../types/alert';
import { formatTime } from '../../utils/formatDate';
import { SeverityBadge } from '../common/SeverityBadge';

interface Props {
  alerts: Alert[];
  focusId: string;
  onFocus: (id: string) => void;
}

export function EvidencePanel({ alerts, focusId, onFocus }: Props) {
  const ips = [...new Set(alerts.map((a) => a.sourceIp))];
  const hosts = [...new Set(alerts.map((a) => a.asset))];
  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-sx-line px-4 py-3">
        <h2 className="panel-title">Evidence & related alerts</h2>
        <p className="mt-0.5 text-[11px] text-sx-mute">{alerts.length} alerts · {hosts.length} host(s) · {ips.length} source IP(s)</p>
      </div>
      <ul className="flex-1 space-y-2 overflow-y-auto p-3">
        {alerts.map((a) => (
          <li key={a.id}>
            <button
              onClick={() => onFocus(a.id)}
              aria-current={a.id === focusId}
              className={`w-full rounded-lg border p-2.5 text-left text-xs transition-colors ${a.id === focusId ? 'border-sx-gold/60 bg-sx-gold/5' : 'border-sx-line bg-sx-elev/40 hover:border-[#3a3a3a]'}`}
            >
              <div className="mb-1 flex items-center justify-between gap-2"><span className="mono text-sx-gold">{a.id}</span><SeverityBadge severity={a.severity} /></div>
              <div className="font-medium">{a.ruleName}</div>
              <dl className="mono mt-1.5 grid grid-cols-[auto_1fr] gap-x-2 gap-y-0.5 text-[11px] text-sx-mute">
                <dt>time</dt><dd>{formatTime(a.timestamp)}</dd>
                <dt>host</dt><dd>{a.asset}</dd>
                <dt>src ip</dt><dd>{a.sourceIp}</dd>
                <dt>event id</dt><dd>{a.eventId}</dd>
              </dl>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
