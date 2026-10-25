import type { SecurityCase } from '../../types/case';
import { timeAgo } from '../../utils/formatDate';
import { SeverityBadge } from '../common/SeverityBadge';
import { StatusBadge } from '../common/StatusBadge';

interface Props {
  cases: SecurityCase[];
  selectedId?: string | null;
  onSelect: (id: string) => void;
}

export function CaseTable({ cases, selectedId, onSelect }: Props) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[820px] text-xs">
        <thead className="border-b border-sx-line bg-sx-bg/40">
          <tr>
            {['Case ID', 'Title', 'Severity', 'Status', 'Assigned', 'Assets', 'Created', 'Updated'].map((h) => <th key={h} className="th">{h}</th>)}
          </tr>
        </thead>
        <tbody className="divide-y divide-sx-line">
          {cases.map((c) => (
            <tr key={c.id} tabIndex={0} onClick={() => onSelect(c.id)} onKeyDown={(e) => e.key === 'Enter' && onSelect(c.id)}
              className={`row-hover ${selectedId === c.id ? 'bg-sx-reddark/15' : ''}`} aria-selected={selectedId === c.id}>
              <td className="td mono text-sx-gold">{c.id}</td>
              <td className="td max-w-[280px] font-medium"><div className="truncate">{c.title}</div></td>
              <td className="td"><SeverityBadge severity={c.severity} /></td>
              <td className="td"><StatusBadge value={c.status} /></td>
              <td className="td">{c.assignee}</td>
              <td className="td mono text-sx-mute">{c.assets.join(', ')}</td>
              <td className="td whitespace-nowrap text-sx-mute">{timeAgo(c.createdAt)}</td>
              <td className="td whitespace-nowrap text-sx-mute">{timeAgo(c.updatedAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
