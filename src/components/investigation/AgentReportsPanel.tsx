import { useState } from "react";
import { apiPost, isBackendConfigured } from "../../services/apiClient";

type ReportResult = {
  reportId: string;
  period: "daily" | "weekly" | "incident";
  markdown: string;
  provider: string;
  model: string;
  sourceCaseCount: number;
  sourceRecordCount: number;
  estimatedInputTokens: number;
  inputTokenBudget: number;
  truncated: boolean;
  generatedAt: string;
};

export function AgentReportsPanel() {
  const [caseId, setCaseId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [report, setReport] = useState<ReportResult | null>(null);

  const generate = async (period: "daily" | "weekly" | "incident") => {
    setBusy(true); setError(""); setReport(null);
    try {
      const result = await apiPost<ReportResult>("/api/ai/report", { period, ...(period === "incident" ? { caseId } : {}) });
      setReport(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Report generation failed.");
    } finally { setBusy(false); }
  };

  return <section className="panel space-y-3 p-4">
    <div>
      <h2 className="text-sm font-semibold">Automated SOC Reports</h2>
      <p className="mt-1 text-[11px] text-sx-mute">Generate tenant-scoped daily/weekly summaries or a case-specific incident report. Reports are saved to the SOC record history.</p>
    </div>
    {!isBackendConfigured && <p className="text-xs text-sx-warn">Connect the SentinelX backend to generate reports.</p>}
    <div className="flex flex-wrap gap-2">
      <button className="btn btn-secondary btn-sm" disabled={!isBackendConfigured || busy} onClick={() => generate("daily")}>{busy ? "Generating…" : "Daily summary"}</button>
      <button className="btn btn-secondary btn-sm" disabled={!isBackendConfigured || busy} onClick={() => generate("weekly")}>Weekly summary</button>
    </div>
    <div className="flex flex-wrap items-end gap-2">
      <label className="block min-w-48 flex-1 text-xs text-sx-mute">Case ID for incident report
        <input className="input mt-1 w-full" value={caseId} onChange={e => setCaseId(e.target.value)} maxLength={120} placeholder="e.g. SX-123456789ABC" disabled={busy} />
      </label>
      <button className="btn btn-primary btn-sm" disabled={!isBackendConfigured || busy || !caseId.trim()} onClick={() => generate("incident")}>Incident report</button>
    </div>
    {error && <p role="alert" className="text-xs text-sx-red">{error}</p>}
    {report && <div className="space-y-2 border-t border-sx-line pt-3">
      <div className="flex flex-wrap gap-2 text-[10px] text-sx-mute">
        <span>{report.period} · {report.provider}/{report.model}</span>
        <span>{report.sourceCaseCount} cases · {report.sourceRecordCount} records</span>
        <span>~{report.estimatedInputTokens}/{report.inputTokenBudget} input tokens</span>
        {report.truncated && <span className="text-sx-warn">Input truncated</span>}
      </div>
      <article className="max-h-[32rem] overflow-auto rounded border border-sx-line bg-black/20 p-3">
        <pre className="whitespace-pre-wrap break-words text-xs leading-5">{report.markdown}</pre>
      </article>
      <p className="mono break-all text-[9px] text-sx-mute">Saved report: {report.reportId} · {new Date(report.generatedAt).toLocaleString()}</p>
      <p className="text-[10px] text-sx-mute">MITRE ATT&CK mappings are evidence-based candidates, not proof. Review before sharing; no response action was executed.</p>
    </div>}
  </section>;
}
