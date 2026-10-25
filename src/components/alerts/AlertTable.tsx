import { Eye } from 'lucide-react';
import type { Alert } from '../../types/alert';
import { formatDateTime, timeAgo } from '../../utils/formatDate';
import { SortHeader } from '../common/Controls';
import { SeverityBadge } from '../common/SeverityBadge';
import { StatusBadge } from '../common/StatusBadge';

export type AlertSortKey = 'id' | 'ruleName' | 'severity' | 'source' | 'asset' | 'sourceIp' | 'timestamp' | 'status';

interface Props {
  alerts: Alert[];
  onOpen: (id: string) => void;
  /** 'recent' = compact dashboard table, 'full' = alert-management table with sortable headers. */
  variant?: 'recent' | 'full';
  sortKey?: AlertSortKey;
  sortDir?: 'asc' | 'desc';
  onSort?: (k: AlertSortKey) => void;
}

export function AlertTable({ alerts, onOpen, variant = 'recent', sortKey, sortDir = 'desc', onSort }: Props) {
  const full = variant === 'full';
  const H = (k: AlertSortKey, label: string) =>
    onSort ? <SortHeader label={label} active={sortKey === k} dir={sortDir} onClick={() => onSort(k)} /> : <th className="th">{label}</th>;

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[820px] text-xs">
        <thead className="border-b border-sx-line bg-sx-bg/40">
          <tr>
            {full && H('id', 'Alert ID')}
            {H('severity', 'Severity')}
            {H('ruleName', full ? 'Rule name' : 'Alert name')}
            {full && H('source', 'Source')}
            {H('asset', 'Affected asset')}
            {H('sourceIp', 'Source IP')}
            {H('timestamp', full ? 'Event time' : 'Detected')}
            {H('status', 'Status')}
            <th className="th text-right">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-sx-line">
          {alerts.map((a) => (
            <tr key={a.id} className="row-hover" onClick={() => onOpen(a.id)} tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && onOpen(a.id)}>
              {full && <td className="td mono text-sx-gold">{a.id}</td>}
              <td className="td"><SeverityBadge severity={a.severity} /></td>
              <td className="td">
                <div className="font-medium">{a.ruleName}</div>
                {!full && <div className="mono text-[10px] text-sx-mute">{a.id}</div>}
              </td>
              {full && <td className="td text-sx-mute">{a.source}</td>}
              <td className="td mono">{a.asset}</td>
              <td className="td mono text-sx-mute">{a.sourceIp}</td>
              <td className="td whitespace-nowrap text-sx-mute" title={formatDateTime(a.timestamp)}>{full ? formatDateTime(a.timestamp) : timeAgo(a.timestamp)}</td>
              <td className="td"><StatusBadge value={a.status} /></td>
              <td className="td text-right">
                <button className="btn btn-sm" onClick={(e) => { e.stopPropagation(); onOpen(a.id); }} aria-label={`View details for ${a.id}`}>
                  <Eye className="h-3 w-3" /> View Details
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
