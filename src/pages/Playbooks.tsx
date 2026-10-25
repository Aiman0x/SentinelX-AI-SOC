import { AlertOctagon, ArrowDown, Bell, CheckCheck, GitBranch, Play, ShieldQuestion, Zap, type LucideIcon } from 'lucide-react';
import { useState } from 'react';
import { ConfirmDialog } from '../components/common/ConfirmDialog';
import { Drawer } from '../components/common/Drawer';
import { Panel } from '../components/common/Controls';
import { ErrorState, LoadingState } from '../components/common/EmptyState';
import { StatusBadge } from '../components/common/StatusBadge';
import { PageHeader } from '../components/layout/PageHeader';
import { useApp } from '../context/AppContext';
import { useData } from '../hooks/useData';
import { loadPlaybooks } from '../services/miscService';
import type { Playbook, PlaybookStep } from '../types/extra';

const stepIcon: Record<PlaybookStep['type'], LucideIcon> = { trigger: Play, enrich: ShieldQuestion, decision: GitBranch, notify: Bell, approval: CheckCheck, action: Zap };
const lifeLabel = { designed: 'Designed only', configured: 'Configured · unverified', executed: 'Executed successfully' };

export default function Playbooks() {
  const { data, loading, error, reload } = useData(loadPlaybooks);
  const { toast } = useApp();
  const [sel, setSel] = useState<Playbook | null>(null);
  const [confirm, setConfirm] = useState<PlaybookStep | null>(null);

  return (
    <>
      <PageHeader title="Response Playbooks" subtitle="Workflow designs for future ActivePieces automation." />
      <div className="mb-4 grid gap-3 rounded-lg border border-sx-line bg-sx-panel p-3 text-xs sm:grid-cols-3">
        <div><StatusBadge value="designed" label="Designed" /><p className="mt-1.5 text-sx-mute">Documented on paper. Not built in any tool.</p></div>
        <div><StatusBadge value="configured" label="Configured" /><p className="mt-1.5 text-sx-mute">Built in ActivePieces but not proven end-to-end.</p></div>
        <div><StatusBadge value="executed" label="Executed" /><p className="mt-1.5 text-sx-mute">A real run completed successfully. None in this prototype.</p></div>
      </div>

      {loading ? <div className="panel"><LoadingState /></div> : error ? <div className="panel"><ErrorState message={error} onRetry={reload} /></div> : (
        <div className="grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
          {(data ?? []).map((p) => (
            <Panel key={p.id} bodyClass="flex h-full flex-col p-4" className="flex flex-col">
              <div className="flex items-start justify-between gap-2">
                <div><div className="mono text-[10px] text-sx-gold">{p.id}</div><h3 className="text-sm font-semibold">{p.name}</h3></div>
                <StatusBadge value={p.lifecycle} label={lifeLabel[p.lifecycle]} />
              </div>
              <p className="mt-2 text-xs text-sx-mute">{p.purpose}</p>
              <dl className="mt-3 flex-1 space-y-2 text-[11px]">
                <div><dt className="label !mb-0.5">Trigger conditions</dt><dd>{p.triggers.join(' · ')}</dd></div>
                <div><dt className="label !mb-0.5">Required evidence</dt><dd>{p.requiredEvidence.join(' · ')}</dd></div>
                <div><dt className="label !mb-0.5">Planned actions</dt><dd>{p.plannedActions.join(' → ')}</dd></div>
                <div><dt className="label !mb-0.5">Approval</dt><dd className="text-sx-warn">{p.approval}</dd></div>
                <div><dt className="label !mb-0.5">Execution status</dt><dd>{p.lastExecuted ? p.lastExecuted : 'Never executed'}</dd></div>
              </dl>
              <button className="btn btn-gold mt-3" onClick={() => setSel(p)}><GitBranch className="h-3.5 w-3.5" /> View workflow</button>
            </Panel>
          ))}
        </div>
      )}

      <Drawer open={!!sel} onClose={() => setSel(null)} title={sel?.name} subtitle={sel && <StatusBadge value={sel.lifecycle} label={lifeLabel[sel.lifecycle]} />} width="max-w-xl">
        {sel && (
          <div className="space-y-1">
            <p className="mb-4 rounded-lg border border-sx-line bg-sx-elev/40 p-2.5 text-[11px] text-sx-mute">Workflow diagram for review. Nothing here runs on a real system from this prototype.</p>
            {sel.steps.map((s, i) => {
              const Icon = stepIcon[s.type];
              return (
                <div key={s.id}>
                  <div className={`rounded-lg border p-3 ${s.disruptive ? 'border-sx-red/50 bg-sx-red/5' : 'border-sx-line bg-sx-panel'}`}>
                    <div className="flex items-center gap-2.5">
                      <span className={`flex h-7 w-7 items-center justify-center rounded-md border ${s.disruptive ? 'border-sx-red/50 text-sx-red' : 'border-sx-gold/30 text-sx-gold'}`}><Icon className="h-3.5 w-3.5" /></span>
                      <div className="flex-1"><div className="text-xs font-medium">{i + 1}. {s.label}</div><div className="text-[10px] uppercase tracking-wider text-sx-mute">{s.type}</div></div>
                      {s.disruptive && <span className="rounded border border-sx-red/50 bg-sx-red/10 px-1.5 py-0.5 text-[9px] font-bold tracking-wider text-[#FF6B66]">DISRUPTIVE</span>}
                    </div>
                    <p className="mt-2 text-[11px] text-sx-mute">{s.detail}</p>
                    {s.branches && <div className="mt-2 flex flex-wrap gap-1.5">{s.branches.map((b) => <span key={b.label} className="rounded border border-sx-line bg-sx-bg px-1.5 py-0.5 text-[10px]"><GitBranch className="mr-1 inline h-2.5 w-2.5 text-sx-gold" />{b.label}</span>)}</div>}
                    {s.disruptive && <button className="btn btn-primary btn-sm mt-3" onClick={() => setConfirm(s)}><AlertOctagon className="h-3 w-3" /> Request approval (simulation)</button>}
                  </div>
                  {i < sel.steps.length - 1 && <div className="flex justify-center py-1 text-sx-mute"><ArrowDown className="h-4 w-4" /></div>}
                </div>
              );
            })}
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={!!confirm}
        danger
        title={`Disruptive action: ${confirm?.label ?? ''}`}
        message="This step would affect a real system (isolate, disable, block or delete). In this prototype nothing is executed. In production this requires authorisation, a logged approval and typed confirmation."
        requireTyped="CONFIRM"
        confirmLabel="Record simulated approval"
        onCancel={() => setConfirm(null)}
        onConfirm={() => { toast(`Simulation only: “${confirm?.label}” was NOT executed on any system.`, 'warn'); setConfirm(null); }}
      />
    </>
  );
}
