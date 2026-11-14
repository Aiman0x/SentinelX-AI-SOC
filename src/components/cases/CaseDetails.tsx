import { FileText, Microscope, Send, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../../context/AppContext';
import { apiPost } from '../../services/apiClient';
import { ANALYSTS, addNote, setAssignee, setCaseStatus } from '../../services/casesService';
import type { Alert } from '../../types/alert';
import type { CaseStatus, SecurityCase } from '../../types/case';
import { formatDateTime } from '../../utils/formatDate';
import { Panel, Select } from '../common/Controls';
import { SeverityBadge } from '../common/SeverityBadge';
import { StatusBadge } from '../common/StatusBadge';
import { IncidentTimeline } from './IncidentTimeline';

const STATUSES: CaseStatus[] = ['open', 'investigating', 'contained', 'resolved', 'closed'];

export function CaseDetails({ c, alerts, onClose, readOnly = false }: { c: SecurityCase; alerts: Alert[]; onClose: () => void; readOnly?: boolean }) {
  const { toast, analyst, openAlert } = useApp();
  const navigate = useNavigate();
  const [note, setNote] = useState('');
  const [report, setReport] = useState<string | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  useEffect(() => { setReport(null); setReportError(null); }, [c.id]);
  const linked = c.alertIds.map((id) => alerts.find((a) => a.id === id || a.eventId === id || a.evidence.includes(id))).filter(Boolean) as Alert[];
  const primaryAlertId = linked[0]?.id ?? c.alertIds.find((id) => alerts.some((a) => a.id === id));

  const generateReport = async () => {
    setReportLoading(true);
    setReportError(null);
    try {
      const result = await apiPost<{ markdown: string }>(`/api/incidents/${encodeURIComponent(c.id)}/report`, {});
      setReport(result.markdown);
      toast('Detection report generated and saved to the SentinelX audit trail.', 'success');
    } catch (error) {
      setReportError(error instanceof Error ? error.message : 'Could not generate detection report.');
    } finally {
      setReportLoading(false);
    }
  };

  const submit = () => {
    if (!note.trim()) return;
    addNote(c.id, analyst, note.trim());
    setNote('');
    toast('Note added (stored in this browser only).', 'success');
  };

  return (
    <div className="space-y-4 anim-fade">
      <Panel
        title={<span className="flex flex-wrap items-center gap-2"><span className="mono text-sx-gold">{c.id}</span> {c.title}</span>}
        right={<button className="btn btn-ghost btn-sm" onClick={onClose} aria-label="Close case"><X className="h-4 w-4" /></button>}
        bodyClass="p-4"
      >
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <SeverityBadge severity={c.severity} /> <StatusBadge value={c.status} />
          <span className="text-[11px] text-sx-mute">Created {formatDateTime(c.createdAt)} · Updated {formatDateTime(c.updatedAt)}</span>
        </div>
        <h3 className="label">Incident overview</h3>
        <p className="text-[13px]">{c.overview}</p>

        {!readOnly && <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <div>
            <span className="label">Case status</span>
            <Select label="Case status" value={c.status} onChange={(v) => { setCaseStatus(c.id, v as CaseStatus, analyst); toast(`Status changed to ${v}.`, 'success'); }}
              options={STATUSES.map((s) => ({ value: s, label: s[0].toUpperCase() + s.slice(1) }))} />
          </div>
          <div>
            <span className="label">Analyst assignment</span>
            <Select label="Assign analyst" value={c.assignee} onChange={(v) => { setAssignee(c.id, v); toast(`Assigned to ${v}.`, 'success'); }}
              options={ANALYSTS.map((s) => ({ value: s, label: s }))} />
          </div>
        </div>}
        {readOnly && <p className="mt-3 text-[11px] text-sx-mute">Read-only backend record. Case updates and assignment controls will be enabled when the write API is ready.</p>}
        <div className="mt-4 flex gap-2">
          <button className="btn btn-primary" onClick={() => primaryAlertId && navigate(`/investigation?alert=${encodeURIComponent(primaryAlertId)}`)} disabled={!primaryAlertId}><Microscope className="h-3.5 w-3.5" /> Open in Investigation</button>
          {c.detectionIncident && <button className="btn btn-gold" onClick={generateReport} disabled={reportLoading}><FileText className="h-3.5 w-3.5" /> {reportLoading ? 'Generating report…' : 'Generate detection report'}</button>}
        </div>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Incident timeline" bodyClass="p-4"><IncidentTimeline entries={c.timeline} /></Panel>
        <div className="space-y-4">
          <Panel title={`Related alerts (${linked.length})`} bodyClass="p-3">
            {linked.length === 0 ? <p className="p-1 text-xs text-sx-mute">No alerts linked.</p> : (
              <ul className="space-y-1.5">
                {linked.map((a) => (
                  <li key={a.id}>
                    <button onClick={() => openAlert(a.id)} className="flex w-full items-center justify-between gap-2 rounded-lg border border-sx-line bg-sx-elev/40 px-3 py-2 text-left text-xs hover:border-sx-gold/40">
                      <span><span className="mono text-sx-gold">{a.id}</span> · {a.ruleName}</span><SeverityBadge severity={a.severity} />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
          <Panel title="Evidence collected" bodyClass="p-4">
            {c.evidence.length === 0 ? <p className="text-xs text-sx-mute">No evidence recorded.</p> : (
              <ul className="space-y-1.5">{c.evidence.map((e) => <li key={e} className="flex gap-2 text-xs"><span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-sx-gold" />{e}</li>)}</ul>
            )}
          </Panel>
          <Panel title="Recommended actions" bodyClass="p-4">
            {c.recommended.length === 0 ? <p className="text-xs text-sx-mute">None.</p> : (
              <ol className="list-decimal space-y-1.5 pl-4 text-xs marker:text-sx-gold">{c.recommended.map((e) => <li key={e}>{e}</li>)}</ol>
            )}
            <p className="mt-2 text-[11px] text-sx-mute">Recommendations only. No response action is executed from this prototype.</p>
          </Panel>
        </div>
      </div>

      <Panel title="Investigation notes" bodyClass="p-4">
        {!readOnly && <div className="flex gap-2">
          <textarea className="input min-h-[60px] resize-y" placeholder="Add an investigation note…" value={note} onChange={(e) => setNote(e.target.value)} aria-label="New investigation note" />
          <button className="btn btn-gold self-end" onClick={submit} disabled={!note.trim()}><Send className="h-3.5 w-3.5" /> Add</button>
        </div>}
        <ul className="mt-3 space-y-2">
          {c.notes.length === 0 && <li className="text-xs text-sx-mute">No notes yet.</li>}
          {c.notes.map((n) => (
            <li key={n.id} className="rounded-lg border border-sx-line bg-sx-elev/40 p-3 text-xs">
              <div className="mb-1 flex justify-between text-[11px] text-sx-mute"><span className="font-medium text-sx-ink">{n.author}</span><span className="mono">{formatDateTime(n.time)}</span></div>
              {n.text}
            </li>
          ))}
        </ul>
        <p className="mt-3 text-[11px] text-sx-mute">{readOnly ? 'Backend case notes are read-only until the notes API is implemented.' : 'Prototype note: cases are saved in this browser’s local storage, which is not a secure database.'}</p>
      </Panel>
      {reportError && <Panel title="Report error" bodyClass="p-3"><p className="text-xs text-sx-red">{reportError}</p></Panel>}
      {report && <Panel title="SentinelX detection report" bodyClass="p-4"><pre className="whitespace-pre-wrap break-words text-xs leading-6 text-sx-ink">{report}</pre></Panel>}
    </div>
  );
}
