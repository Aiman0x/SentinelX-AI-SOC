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
            {['Case ID', 'Record type', 'Title', 'Severity', 'Status', 'Assigned', 'Assets', 'Created', 'Updated'].map((h) => <th key={h} className="th">{h}</th>)}
          </tr>
        </thead>
        <tbody className="divide-y divide-sx-line">
          {cases.map((c) => (
            <tr key={c.id} tabIndex={0} onClick={() => onSelect(c.id)} onKeyDown={(e) => e.key === 'Enter' && onSelect(c.id)}
              className={`row-hover ${selectedId === c.id ? 'bg-sx-reddark/15' : ''}`} aria-selected={selectedId === c.id}>
              <td className="td mono text-sx-gold">{c.id}</td>
              <td className="td">{c.detectionIncident ? <span className="rounded border border-sx-ok/40 bg-sx-ok/5 px-2 py-1 text-[10px] text-sx-ok">Live detection</span> : c.legacyRecord ? <span className="rounded border border-sx-warn/40 bg-sx-warn/5 px-2 py-1 text-[10px] text-sx-warn">Legacy record</span> : <span className="rounded border border-sx-line px-2 py-1 text-[10px] text-sx-mute">Case</span>}</td>
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
