import { Bell, FileSearch, GitCommitHorizontal, MessageSquare, Cpu, type LucideIcon } from 'lucide-react';
import type { TimelineEntry } from '../../types/case';
import { formatDateTime } from '../../utils/formatDate';

const kindIcon: Record<TimelineEntry['kind'], { icon: LucideIcon; cls: string }> = {
  detection: { icon: Bell, cls: 'text-sx-red border-sx-red/40 bg-sx-red/10' },
  analyst: { icon: MessageSquare, cls: 'text-sx-gold border-sx-gold/40 bg-sx-gold/10' },
  status: { icon: GitCommitHorizontal, cls: 'text-sx-ink border-sx-line bg-sx-elev' },
  evidence: { icon: FileSearch, cls: 'text-sx-ok border-sx-ok/40 bg-sx-ok/10' },
  system: { icon: Cpu, cls: 'text-sx-mute border-sx-line bg-sx-elev' },
};

export function IncidentTimeline({ entries }: { entries: TimelineEntry[] }) {
  const sorted = [...entries].sort((a, b) => +new Date(a.time) - +new Date(b.time));
  if (sorted.length === 0) return <p className="text-xs text-sx-mute">No timeline entries yet.</p>;
  return (
    <ol className="relative space-y-4 border-l border-sx-line pl-6">
      {sorted.map((e) => {
        const { icon: Icon, cls } = kindIcon[e.kind];
        return (
          <li key={e.id} className="relative">
            <span className={`absolute -left-[37px] flex h-6 w-6 items-center justify-center rounded-full border ${cls}`}><Icon className="h-3 w-3" aria-hidden /></span>
            <div className="text-xs font-medium">{e.title}</div>
            <div className="text-xs text-sx-mute">{e.detail}</div>
            <div className="mono mt-0.5 text-[10px] text-[#666]">{formatDateTime(e.time)}</div>
          </li>
        );
      })}
    </ol>
  );
}
