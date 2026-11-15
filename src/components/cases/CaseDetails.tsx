import { FileText, Microscope, Send, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../../context/AppContext';
import { apiGet, apiPost, isBackendConfigured } from '../../services/apiClient';
import { ANALYSTS, addNote, setAssignee, setCaseStatus } from '../../services/casesService';
import type { Alert } from '../../types/alert';
import type { CaseNote, CaseStatus, SecurityCase } from '../../types/case';
import { formatDateTime } from '../../utils/formatDate';
import { Panel, Select } from '../common/Controls';
import { SeverityBadge } from '../common/SeverityBadge';
import { StatusBadge } from '../common/StatusBadge';
import { IncidentTimeline } from './IncidentTimeline';

const STATUSES: CaseStatus[] = ['open', 'investigating', 'contained', 'resolved', 'closed'];
const listValue = (value: unknown): string[] => Array.isArray(value) ? value.map(item => typeof item === 'string' ? item : JSON.stringify(item)) : [];

type BackendNote = { id: string; note_type?: string; body: string; author: string; created_at: string };

export function CaseDetails({ c, alerts, onClose, onUpdated, readOnly = false }: {
  c: SecurityCase; alerts: Alert[]; onClose: () => void; onUpdated?: () => void; readOnly?: boolean;
}) {
  const { toast, analyst, openAlert } = useApp();
  const navigate = useNavigate();
  const [note, setNote] = useState('');
  const [notes, setNotes] = useState<CaseNote[]>(c.notes);
  const [status, setStatus] = useState<CaseStatus>(c.status);
  const [assignee, setAssigneeValue] = useState(c.assignee);
  const [saving, setSaving] = useState(false);
  const [notesError, setNotesError] = useState('');
  const [report, setReport] = useState<string | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);

  useEffect(() => {
    setNotes(c.notes);
    setStatus(c.status);
    setAssigneeValue(c.assignee);
    setReport(null);
    setReportError(null);
  }, [c.id, c.notes, c.status, c.assignee]);

  useEffect(() => {
    if (!isBackendConfigured || readOnly || c.detectionIncident) return;
    let cancelled = false;
    apiGet<{ data?: BackendNote[] }>(`/api/notes?caseId=${encodeURIComponent(c.id)}`)
      .then(result => {
        if (cancelled) return;
        setNotes((result.data ?? []).map(item => ({
          id: item.id, author: item.author || 'Analyst', time: item.created_at,
          text: item.body || ''
        })));
      })
      .catch(error => { if (!cancelled) setNotesError(error instanceof Error ? error.message : 'Could not load case notes.'); });
    return () => { cancelled = true; };
  }, [c.id, readOnly, c.detectionIncident]);

  const linked = c.alertIds.map((id) => alerts.find((a) => a.id === id || a.eventId === id || a.evidence.includes(id))).filter(Boolean) as Alert[];

  const updateCase = async (patch: { status?: CaseStatus; assignee?: string }) => {
    if (saving || readOnly || c.detectionIncident) return;
    setSaving(true);
    try {
      if (isBackendConfigured) {
        await apiPost(`/api/cases/${encodeURIComponent(c.id)}`, patch);
      } else if (patch.status) {
        setCaseStatus(c.id, patch.status, analyst);
      } else if (patch.assignee !== undefined) {
        setAssignee(c.id, patch.assignee);
      }
      if (patch.status) setStatus(patch.status);
      if (patch.assignee !== undefined) setAssigneeValue(patch.assignee);
      toast('Case updated and saved.', 'success');
      onUpdated?.();
    } catch (error) {
      toast(error instanceof Error ? error.message : 'Could not update case.', 'error');
    } finally { setSaving(false); }
  };

  const submit = async () => {
    const text = note.trim();
    if (!text || readOnly || c.detectionIncident) return;
    setSaving(true);
    try {
      if (isBackendConfigured) {
        const result = await apiPost<{ note?: { id: string; text: string; author: string; createdAt: string } }>('/api/notes', { caseId: c.id, text });
        const saved = result.note;
        if (!saved) throw new Error('Backend did not confirm the note save.');
        setNotes(previous => [{ id: saved.id, author: saved.author, time: saved.createdAt, text: saved.text }, ...previous]);
      } else {
        addNote(c.id, analyst, text);
        setNotes(previous => [{ id: `local-${Date.now()}`, author: analyst, time: new Date().toISOString(), text }, ...previous]);
      }
      setNote('');
      setNotesError('');
      toast('Investigation note saved.', 'success');
      onUpdated?.();
    } catch (error) {
      toast(error instanceof Error ? error.message : 'Could not save note.', 'error');
    } finally { setSaving(false); }
  };

  const generateReport = async () => {
    setReportLoading(true); setReportError(null);
    try {
      const result = await apiPost<{ markdown: string }>(`/api/incidents/${encodeURIComponent(c.id)}/report`, {});
      setReport(result.markdown);
      toast('Detection report generated and saved to the SentinelX audit trail.', 'success');
    } catch (error) {
      setReportError(error instanceof Error ? error.message : 'Could not generate detection report.');
    } finally { setReportLoading(false); }
  };

  const analysis = c.analysis ?? {};
  const analysisSections = [
    { title: 'Observed facts', value: analysis.facts },
    { title: 'Suspicious indicators', value: analysis.suspicious },
    { title: 'Assumptions', value: analysis.assumptions },
    { title: 'Unknowns / evidence gaps', value: analysis.unknowns },
    { title: 'Alternative explanations', value: analysis.alternatives },
    { title: 'Detection recommendations', value: analysis.detections },
  ].filter(section => listValue(section.value).length > 0);

  return (
    <div className="space-y-4 anim-fade">
      <Panel
        title={<span className="flex flex-wrap items-center gap-2"><span className="mono text-sx-gold">{c.id}</span> {c.title}</span>}
        right={<button className="btn btn-ghost btn-sm" onClick={onClose} aria-label="Close case"><X className="h-4 w-4" /></button>}
        bodyClass="p-4"
      >
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <SeverityBadge severity={c.severity} /> <StatusBadge value={status} />
          {c.legacyRecord && <span className="rounded border border-sx-warn/40 bg-sx-warn/5 px-2 py-1 text-[10px] text-sx-warn">Legacy record · not a live detection</span>}
          {c.detectionIncident && <span className="rounded border border-sx-ok/40 bg-sx-ok/5 px-2 py-1 text-[10px] text-sx-ok">Rule-based live detection</span>}
          <span className="text-[11px] text-sx-mute">Created {formatDateTime(c.createdAt)} · Updated {formatDateTime(c.updatedAt)}</span>
        </div>
        {(c.dataOrigin || c.sourceSchema || c.sourceEventId) && (
          <div className="mb-3 grid gap-2 rounded border border-sx-line bg-sx-elev/30 p-3 text-[11px] sm:grid-cols-3">
            <div><div className="label">Data origin</div><span className="mono">{c.dataOrigin || 'Not recorded'}</span></div>
            <div><div className="label">Source schema</div><span className="mono">{c.sourceSchema || 'Not recorded'}</span></div>
            <div><div className="label">Source event reference</div><span className="mono break-all">{c.sourceEventId || 'Not recorded'}</span></div>
          </div>
        )}
        <h3 className="label">Incident overview</h3>
        <p className="text-[13px] leading-6">{c.overview}</p>

        {!readOnly && !c.detectionIncident && (
          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            <div>
              <span className="label">Case status</span>
              <Select label="Case status" value={status} onChange={(v) => void updateCase({ status: v as CaseStatus })}
                options={STATUSES.map((s) => ({ value: s, label: s[0].toUpperCase() + s.slice(1) }))} />
            </div>
            <div>
              <span className="label">Analyst assignment</span>
              <Select label="Assign analyst" value={assignee} onChange={(v) => void updateCase({ assignee: v })}
                options={ANALYSTS.map((s) => ({ value: s, label: s }))} />
            </div>
          </div>
        )}
        {readOnly && <p className="mt-3 text-[11px] text-sx-mute">This record is read-only for your current role.</p>}
        {c.detectionIncident && <p className="mt-3 text-[11px] text-sx-mute">Detection incident state is currently read-only. Review the linked events and generate a rule-based detection report.</p>}
        <div className="mt-4 flex flex-wrap gap-2">
          <button className="btn btn-primary" onClick={() => navigate(`/investigation?case=${encodeURIComponent(c.id)}`)}><Microscope className="h-3.5 w-3.5" /> Investigate this case</button>
          {c.detectionIncident && <button className="btn btn-gold" onClick={generateReport} disabled={reportLoading}><FileText className="h-3.5 w-3.5" /> {reportLoading ? 'Generating report…' : 'Generate detection report'}</button>}
        </div>
      </Panel>

      {c.analysis && (
        <Panel title="Historical analysis from the original case record" bodyClass="p-4">
          <div className="mb-3 flex flex-wrap gap-2 text-[11px]">
            {typeof analysis.verdict === 'string' && <span className="rounded border border-sx-line px-2 py-1">Previous verdict: {analysis.verdict}</span>}
            {typeof analysis.confidence === 'number' && <span className="rounded border border-sx-line px-2 py-1">Previous confidence: {analysis.confidence}/100</span>}
            {typeof analysis.risk_score === 'number' && <span className="rounded border border-sx-line px-2 py-1">Previous risk score: {analysis.risk_score}/100</span>}
          </div>
          <p className="mb-3 text-[10px] text-sx-warn">This is a historical report stored with the case. It is not a new investigation or proof that the current host state has been verified.</p>
          <div className="grid gap-3 md:grid-cols-2">
            {analysisSections.map(section => (
              <div key={section.title} className="rounded border border-sx-line p-3">
                <h4 className="mb-2 text-xs font-semibold">{section.title}</h4>
                <ul className="list-disc space-y-1 pl-4 text-xs text-sx-mute">{listValue(section.value).map((item, index) => <li key={index}>{item}</li>)}</ul>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {c.rawEvidence && (
        <Panel title="Original source evidence (stored with this record)" bodyClass="p-4">
          <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words text-[11px] text-sx-mute">{c.rawEvidence}</pre>
        </Panel>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Incident timeline" bodyClass="p-4"><IncidentTimeline entries={c.timeline} /></Panel>
        <div className="space-y-4">
          <Panel title={`Related alerts (${linked.length})`} bodyClass="p-3">
            {linked.length === 0 ? <div className="space-y-1 p-1 text-xs text-sx-mute"><p>No detection alerts are linked to this record.</p>{c.sourceEventId && <p className="mono break-all">Original source event: {c.sourceEventId}</p>}</div> : (
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
            {c.evidence.length === 0 ? <p className="text-xs text-sx-mute">No separate evidence snapshots are linked to this case.</p> : (
              <ul className="space-y-1.5">{c.evidence.map((e) => <li key={e} className="flex gap-2 text-xs"><span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-sx-gold" />{e}</li>)}</ul>
            )}
          </Panel>
          <Panel title="Recommended actions" bodyClass="p-4">
            {c.recommended.length === 0 ? <p className="text-xs text-sx-mute">None.</p> : (
              <ol className="list-decimal space-y-1.5 pl-4 text-xs marker:text-sx-gold">{c.recommended.map((e) => <li key={e}>{e}</li>)}</ol>
            )}
            <p className="mt-2 text-[11px] text-sx-mute">Recommendations only. No response action is executed from this report.</p>
          </Panel>
        </div>
      </div>

      <Panel title="Investigation notes" bodyClass="p-4">
        {!readOnly && !c.detectionIncident && <div className="flex gap-2">
          <textarea className="input min-h-[60px] resize-y" placeholder="Add an investigation note…" value={note} onChange={(e) => setNote(e.target.value)} aria-label="New investigation note" disabled={saving} />
          <button className="btn btn-gold self-end" onClick={() => void submit()} disabled={!note.trim() || saving}><Send className="h-3.5 w-3.5" /> Add</button>
        </div>}
        {notesError && <p className="mt-2 text-xs text-sx-red">{notesError}</p>}
        <ul className="mt-3 space-y-2">
          {notes.length === 0 && <li className="text-xs text-sx-mute">No notes yet.</li>}
          {notes.map((n) => (
            <li key={n.id} className="rounded-lg border border-sx-line bg-sx-elev/40 p-3 text-xs">
              <div className="mb-1 flex justify-between text-[11px] text-sx-mute"><span className="font-medium text-sx-ink">{n.author}</span><span className="mono">{formatDateTime(n.time)}</span></div>
              {n.text}
            </li>
          ))}
        </ul>
        <p className="mt-3 text-[11px] text-sx-mute">{isBackendConfigured ? 'Notes and case changes are stored in the authenticated SentinelX backend and audit logged.' : 'Demo-mode notes are stored in this browser only.'}</p>
      </Panel>
      {reportError && <Panel title="Report error" bodyClass="p-3"><p className="text-xs text-sx-red">{reportError}</p></Panel>}
      {report && <Panel title="SentinelX detection report" bodyClass="p-4"><pre className="whitespace-pre-wrap break-words text-xs leading-6 text-sx-ink">{report}</pre></Panel>}
    </div>
  );
}
