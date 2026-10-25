import { ChevronDown, ChevronRight, Link2 } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import type { Alert } from '../../types/alert';
import { formatDateTime } from '../../utils/formatDate';
import { SeverityBadge } from '../common/SeverityBadge';
import { AnalystAssistant } from './AnalystAssistant';
import { EvidencePanel } from './EvidencePanel';

/** Related = same asset, same source IP, or explicitly correlated with the primary alert. */
export function relatedTo(primary: Alert, all: Alert[]): Alert[] {
  return all
    .filter((a) => a.id === primary.id || a.asset === primary.asset || a.sourceIp === primary.sourceIp || primary.relatedAlertIds.includes(a.id) || a.relatedAlertIds.includes(primary.id))
    .sort((a, b) => +new Date(a.timestamp) - +new Date(b.timestamp));
}

function why(a: Alert, primary: Alert): string[] {
  const r: string[] = [];
  if (a.id === primary.id) return ['primary alert'];
  if (a.asset === primary.asset) r.push('same host');
  if (a.sourceIp === primary.sourceIp) r.push('same source IP');
  if (primary.relatedAlertIds.includes(a.id) || a.relatedAlertIds.includes(primary.id)) r.push('correlated');
  return r;
}

export function InvestigationWorkspace({ primary, all, onChangePrimary }: { primary: Alert; all: Alert[]; onChangePrimary?: (id: string) => void }) {
  const related = useMemo(() => relatedTo(primary, all), [primary, all]);
  const [focusId, setFocusId] = useState(primary.id);
  const [open, setOpen] = useState<Set<string>>(new Set([primary.id]));

  useEffect(() => { setFocusId(primary.id); setOpen(new Set([primary.id])); }, [primary.id]);

  const toggle = (id: string) => setOpen((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const focus = (id: string) => { setFocusId(id); setOpen((s) => new Set(s).add(id)); document.getElementById(`tl-${id}`)?.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); };
  void onChangePrimary;

  return (
    <div className="grid gap-4 xl:h-[calc(100vh-230px)] xl:min-h-[560px] xl:grid-cols-[300px_minmax(0,1fr)_380px]">
      <section className="panel overflow-hidden xl:h-full"><EvidencePanel alerts={related} focusId={focusId} onFocus={focus} /></section>

      <section className="panel flex flex-col overflow-hidden xl:h-full">
        <div className="border-b border-sx-line px-4 py-3">
          <h2 className="panel-title">Investigation timeline</h2>
          <p className="mt-0.5 text-[11px] text-sx-mute">Chronological. Critical/high events are highlighted. Links show why events are related.</p>
        </div>
        <ol className="relative flex-1 space-y-3 overflow-y-auto p-4 pl-10">
          <span className="absolute bottom-6 left-[26px] top-6 w-px bg-gradient-to-b from-sx-red/60 via-sx-line to-transparent" aria-hidden />
          {related.map((a) => {
            const hot = a.severity === 'critical' || a.severity === 'high';
            const isOpen = open.has(a.id);
            return (
              <li key={a.id} id={`tl-${a.id}`} className="relative">
                <span className={`absolute -left-[22px] top-3 h-3 w-3 rounded-full border-2 border-sx-bg ${hot ? 'bg-sx-red shadow-[0_0_8px_#E53935]' : 'bg-[#555]'}`} aria-hidden />
                <div className={`rounded-lg border transition-colors ${a.id === focusId ? 'border-sx-gold/60' : hot ? 'border-sx-red/30' : 'border-sx-line'} ${hot ? 'bg-sx-red/[0.04]' : 'bg-sx-elev/30'}`}>
                  <button className="flex w-full items-center gap-3 px-3 py-2.5 text-left" onClick={() => { setFocusId(a.id); toggle(a.id); }} aria-expanded={isOpen}>
                    {isOpen ? <ChevronDown className="h-3.5 w-3.5 shrink-0 text-sx-mute" /> : <ChevronRight className="h-3.5 w-3.5 shrink-0 text-sx-mute" />}
                    <span className="mono w-16 shrink-0 text-[11px] text-sx-mute">{formatDateTime(a.timestamp).slice(11)}</span>
                    <span className="min-w-0 flex-1"><span className="block truncate text-xs font-medium">{a.ruleName}</span><span className="mono block truncate text-[10px] text-sx-mute">{a.asset} · {a.sourceIp}</span></span>
                    <SeverityBadge severity={a.severity} />
                  </button>
                  {isOpen && (
                    <div className="space-y-2.5 border-t border-sx-line px-4 py-3 text-xs anim-fade">
                      <p>{a.summary}</p>
                      <ul className="space-y-1">{a.evidence.map((e) => <li key={e} className="flex gap-2"><span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-sx-gold" />{e}</li>)}</ul>
                      <pre className="mono max-h-36 overflow-auto rounded border border-sx-line bg-sx-bg p-2 text-[10px] text-[#cfcfcf]">{JSON.stringify(a.rawEvent, null, 2)}</pre>
                      <div className="flex flex-wrap gap-1.5">
                        {why(a, primary).map((w) => <span key={w} className="inline-flex items-center gap-1 rounded border border-sx-gold/30 bg-sx-gold/5 px-1.5 py-0.5 text-[10px] text-sx-gold"><Link2 className="h-2.5 w-2.5" /> {w}</span>)}
                      </div>
                    </div>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      </section>

      <section className="panel overflow-hidden xl:h-full"><AnalystAssistant alerts={related} focus={all.find((x) => x.id === focusId) ?? primary} /></section>
    </div>
  );
}
