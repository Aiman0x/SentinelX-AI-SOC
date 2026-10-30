import { ExternalLink, FolderPlus, Microscope, Target } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../../context/AppContext';
import { useAlerts } from '../../hooks/useAlerts';
import { updateAlert } from '../../services/alertsService';
import { createCaseFromAlert } from '../../services/casesService';
import { formatDateTime } from '../../utils/formatDate';
import { Drawer } from '../common/Drawer';
import { SeverityBadge } from '../common/SeverityBadge';
import { DemoTag, StatusBadge } from '../common/StatusBadge';
import { isDemoMode } from '../../services/apiClient';

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-5">
      <h3 className="label">{title}</h3>
      {children}
    </section>
  );
}

export function AlertDetails({ alertId, onClose }: { alertId: string | null; onClose: () => void }) {
  const { alerts } = useAlerts();
  const { toast, openAlert, analyst } = useApp();
  const navigate = useNavigate();
  const alert = alertId ? alerts.find((a) => a.id === alertId) : undefined;

  if (!alertId || !alert) return null;

  const related = alert.relatedAlertIds.map((id) => alerts.find((a) => a.id === id)).filter(Boolean) as typeof alerts;

  const makeCase = () => {
    const had = !!alert.caseId;
    const c = createCaseFromAlert(alert, analyst);
    toast(had ? `Opening existing case ${c.id}` : `Demo case ${c.id} created (stored in this browser only).`, 'success');
    onClose();
    navigate(`/cases?case=${c.id}`);
  };
  const investigate = () => {
    if (isDemoMode && alert.status === 'open') updateAlert(alert.id, { status: 'investigating' });
    onClose();
    navigate(`/investigation?alert=${alert.id}`);
  };

  return (
    <Drawer
      open
      onClose={onClose}
      title={<span className="flex items-center gap-2">{alert.ruleName} {isDemoMode && <DemoTag />}</span>}
      subtitle={<span className="mono">{alert.id} · Event ID {alert.eventId} · {formatDateTime(alert.timestamp)}</span>}
      footer={
        isDemoMode ? (
          <>
            <button className="btn" onClick={() => { updateAlert(alert.id, { status: 'false_positive' }); toast('Marked as false positive (local demo state).', 'info'); }}>False positive</button>
            <button className="btn" onClick={() => { updateAlert(alert.id, { status: 'resolved' }); toast('Alert marked resolved (local demo state).', 'success'); }}>Resolve</button>
            <button className="btn btn-gold" onClick={makeCase}><FolderPlus className="h-3.5 w-3.5" /> {alert.caseId ? 'Open Case' : 'Create Case'}</button>
            <button className="btn btn-primary" onClick={investigate}><Microscope className="h-3.5 w-3.5" /> Investigate</button>
          </>
        ) : (
          <>
            {alert.caseId && <button className="btn btn-gold" onClick={() => { onClose(); navigate(`/cases?case=${alert.caseId}`); }}>Open Case</button>}
            <button className="btn btn-primary" onClick={investigate}><Microscope className="h-3.5 w-3.5" /> View Investigations</button>
          </>
        )
      }
    >
      <div className="mb-5 flex flex-wrap items-center gap-2">
        <SeverityBadge severity={alert.severity} />
        <StatusBadge value={alert.status} />
        <span className="rounded-md border border-sx-line px-2 py-0.5 text-[11px] text-sx-mute">{alert.source}</span>
      </div>

      {!isDemoMode && <p className="mb-4 rounded border border-sx-line bg-sx-panel p-2 text-[11px] text-sx-mute">Backend alert record · read-only. Triage updates and case creation will be enabled when their write APIs are complete.</p>}
      <Section title="Alert summary">
        <p className="text-[13px]">{alert.summary}</p>
        <dl className="mt-3 grid grid-cols-2 gap-3 rounded-lg border border-sx-line bg-sx-panel p-3 text-xs">
          <div><dt className="text-sx-mute">Affected asset</dt><dd className="mono mt-0.5">{alert.asset}</dd></div>
          <div><dt className="text-sx-mute">Source IP</dt><dd className="mono mt-0.5">{alert.sourceIp}</dd></div>
        </dl>
      </Section>

      <Section title="Evidence">
        <ul className="space-y-1.5">
          {alert.evidence.map((e) => (
            <li key={e} className="flex gap-2 text-xs"><span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-sx-gold" />{e}</li>
          ))}
        </ul>
      </Section>

      <Section title="Raw event data">
        <pre className="mono max-h-56 overflow-auto rounded-lg border border-sx-line bg-sx-bg p-3 text-[11px] leading-relaxed text-[#cfcfcf]">{JSON.stringify(alert.rawEvent, null, 2)}</pre>
      </Section>

      <Section title="Related events">
        {related.length === 0 ? (
          <p className="text-xs text-sx-mute">No related alerts recorded.</p>
        ) : (
          <ul className="space-y-1.5">
            {related.map((r) => (
              <li key={r.id}>
                <button className="flex w-full items-center justify-between gap-2 rounded-lg border border-sx-line bg-sx-panel px-3 py-2 text-left text-xs hover:border-sx-gold/40" onClick={() => openAlert(r.id)}>
                  <span><span className="mono text-sx-gold">{r.id}</span> · {r.ruleName}</span>
                  <SeverityBadge severity={r.severity} />
                </button>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="MITRE ATT&CK">
        {alert.mitre.length === 0 ? (
          <p className="text-xs text-sx-mute">No technique mapped — the data does not support a mapping.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {alert.mitre.map((m) => (
              <a key={m.id} href={`https://attack.mitre.org/techniques/${m.id.replace('.', '/')}/`} target="_blank" rel="noreferrer noopener"
                className="inline-flex items-center gap-1.5 rounded-md border border-sx-gold/30 bg-sx-gold/5 px-2 py-1 text-xs hover:bg-sx-gold/10">
                <Target className="h-3 w-3 text-sx-gold" /> <span className="mono text-sx-gold">{m.id}</span> {m.name} <span className="text-sx-mute">· {m.tactic}</span> <ExternalLink className="h-3 w-3 text-sx-mute" />
              </a>
            ))}
          </div>
        )}
      </Section>

      <Section title="Recommended next steps">
        <ol className="list-decimal space-y-1.5 pl-4 text-xs marker:text-sx-gold">
          {alert.nextSteps.map((s) => <li key={s}>{s}</li>)}
        </ol>
        <p className="mt-2 text-[11px] text-sx-mute">Recommendations only — SentinelX does not execute response actions in this prototype.</p>
      </Section>

      {alert.caseId && (
        <Section title="Linked case">
          <button className="btn btn-sm" onClick={() => { onClose(); navigate(`/cases?case=${alert.caseId}`); }}>{alert.caseId} →</button>
        </Section>
      )}
    </Drawer>
  );
}
