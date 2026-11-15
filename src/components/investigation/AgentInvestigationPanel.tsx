import { useCallback, useEffect, useRef, useState } from "react";
import { apiGet, apiPost, isBackendConfigured } from "../../services/apiClient";

type AgentResult = {
  agent: string;
  plan: string[];
  steps: { step: number; tool: string; rationale: string; result: unknown; attempts?: number; verification?: { status: "consistent" | "partial" | "unverified"; summary: string; supportedFindings: string[]; gaps: string[]; contradictions: string[] } }[];
  conclusion: string;
  provider: string;
  model: string;
  toolCalls: number;
  maxSteps: number;
  accessMode: string;
  estimatedInputTokens?: number;
  inputTokenBudget?: number;
  inputTruncated?: boolean;
  retries?: number;
  evidenceAssessment?: { consistent: number; partial: number; unverified: number; method: string };
  runId?: string;
  caseId?: string | null;
  generatedAt: string;
};

type SavedAgentRun = {
  runId: string;
  caseId?: string | null;
  generatedAt: string;
  conclusion: string;
  toolCalls: number;
  provider?: string;
  model?: string;
  evidenceAssessment?: { consistent: number; partial: number; unverified: number; method: string };
};

const AGENT_NAME = "SentinelX SOC Investigator v1";

export function AgentInvestigationPanel({ caseId }: { caseId?: string }) {
  const [prompt, setPrompt] = useState(caseId ? "Investigate this case using the original event evidence and connected read-only security tools. Verify the source event, correlate relevant host/account activity around the event time, distinguish historical AI conclusions from newly collected evidence, and report observed facts, hypotheses, confidence, evidence gaps, contradictions and defensive next steps. Do not execute response actions." : "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<AgentResult | null>(null);
  const [history, setHistory] = useState<SavedAgentRun[]>([]);
  const autoStartedCase = useRef<string | null>(null);

  useEffect(() => {
    if (!isBackendConfigured) { setHistory([]); return; }
    let active = true;
    const endpoint = caseId ? `/api/ai/agent/runs?caseId=${encodeURIComponent(caseId)}` : "/api/ai/agent/runs";
    apiGet<{ data?: SavedAgentRun[] }>(endpoint)
      .then(response => { if (active) setHistory(response.data ?? []); })
      .catch(() => { if (active) setHistory([]); });
    return () => { active = false; };
  }, [caseId]);

  useEffect(() => {
    if (caseId) {
      setPrompt("Investigate this case using the original event evidence and connected read-only security tools. Verify the source event, correlate relevant host/account activity around the event time, distinguish historical AI conclusions from newly collected evidence, and report observed facts, hypotheses, confidence, evidence gaps, contradictions and defensive next steps. Do not execute response actions.");
      setResult(null);
      setError("");
    }
  }, [caseId]);

  const run = useCallback(async () => {
    setBusy(true); setError(""); setResult(null);
    const task = caseId
      ? `Investigate case ${caseId} end-to-end. Start with the original linked source event IDs and exact affected host/account. Query the connected Wazuh raw archive and other relevant read-only telemetry for the source event and surrounding activity (authentication, logon type, source/destination IP, process creation, service installation/start, account and privilege changes). Correlate events by host, account and timestamp; identify process names and parent/child context when telemetry provides them. Verify whether the alert title and MITRE mapping are actually supported. Separate observed facts, benign explanations and attack hypotheses. State what evidence is missing, confidence with reasons, and prioritized defensive next steps. Do not execute response actions or claim data you did not retrieve.`
      : prompt;
    if (caseId) setPrompt(task);
    try {
      const response = await apiPost<AgentResult>("/api/ai/agent", { prompt: task, caseId });
      setResult(response);
      if (response.runId) setHistory(previous => [response as SavedAgentRun, ...previous.filter(item => item.runId !== response.runId)]);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Agent investigation failed.");
    } finally { setBusy(false); }
  }, [prompt, caseId]);

  useEffect(() => {
    if (!caseId || !isBackendConfigured || autoStartedCase.current === caseId) return;
    autoStartedCase.current = caseId;
    void run();
  }, [caseId, run]);

  return <section className="panel space-y-3 p-4">
    <div>
      <h2 className="text-sm font-semibold">Autonomous SOC Agent</h2>
      {caseId && <p className="mt-1 text-[11px] text-sx-gold">Investigation target: <span className="mono">{caseId}</span> · case context will be loaded server-side.</p>}
      <p className="mt-1 text-[11px] text-sx-mute">{AGENT_NAME} is the single centrally managed SentinelX investigation agent. It plans the investigation, selects only tools connected to your account, collects read-only evidence and produces an evidence-backed conclusion.</p>
    </div>
    {!isBackendConfigured && <p className="text-xs text-sx-warn">Connect the SentinelX backend to run the agent.</p>}
    <div className="flex flex-wrap gap-2">
      <button type="button" className="btn btn-secondary btn-sm" disabled={busy} onClick={() => setPrompt("Threat hunt: Form a testable hypothesis about suspicious activity in my connected telemetry. Query relevant logs and security tools, correlate timestamps, users, hosts and source IPs, then report evidence, alternative explanations, confidence and candidate MITRE ATT&CK mappings. Do not execute response actions.")}>Threat hunt</button>
      <button type="button" className="btn btn-secondary btn-sm" disabled={busy} onClick={() => setPrompt("Phishing triage: Analyze the suspicious email, URL or domain details I provide. Use my connected reputation and security tools for read-only checks. Examine domain/IP reputation, URL indicators and available telemetry, distinguish malicious indicators from inconclusive evidence, and recommend safe defensive next steps. Do not open links or execute files.")}>Phishing triage</button>
    </div>
    <label className="block text-xs text-sx-mute">Investigation task
      <textarea className="input mt-1 min-h-24 w-full" value={prompt} onChange={e=>setPrompt(e.target.value)} maxLength={12000} placeholder="Investigate this alert or indicator. Identify suspicious activity, gather relevant evidence from my connected tools, and explain the likely cause and defensive next steps." disabled={busy}/>
    </label>
    <div className="flex flex-wrap items-end gap-3">
      <button className="btn btn-primary btn-sm" onClick={run} disabled={!isBackendConfigured||busy||!prompt.trim()}>{busy ? "Investigating…" : "Run agent investigation"}</button>
      <span className="text-[10px] text-sx-mute">Case-specific investigations auto-start · Fixed agent/model · Read-only · 5 connector attempts · 1 controlled retry</span>
    </div>
    {caseId && history.length > 0 && <div className="space-y-2 border-t border-sx-line pt-3">
      <h3 className="label">Saved investigation history ({history.length})</h3>
      {history.filter(item => item.runId !== result?.runId).slice(0, 5).map(item => (
        <details key={item.runId} className="rounded border border-sx-line p-2">
          <summary className="cursor-pointer text-xs">{new Date(item.generatedAt).toLocaleString()} · {item.toolCalls} tool call(s) · {item.evidenceAssessment?.consistent ?? 0} consistent / {item.evidenceAssessment?.partial ?? 0} partial / {item.evidenceAssessment?.unverified ?? 0} unverified</summary>
          <p className="mt-2 whitespace-pre-wrap text-xs text-sx-mute">{item.conclusion}</p>
          <p className="mono mt-2 text-[9px] text-sx-mute">Run {item.runId}</p>
        </details>
      ))}
    </div>}
    {error && <p role="alert" className="text-xs text-sx-red">{error}</p>}
    {result && <div className="space-y-3 border-t border-sx-line pt-3">
      <div className="flex flex-wrap gap-2 text-[10px] text-sx-mute">{result.runId && <span className="mono">Saved run {result.runId}</span>}<span>{result.agent || AGENT_NAME}</span><span>{result.provider} · {result.model}</span><span>{result.toolCalls}/{result.maxSteps} connector attempts</span><span>{result.retries || 0} retries</span><span>{result.accessMode}</span>{result.estimatedInputTokens !== undefined && <span>~{result.estimatedInputTokens} input tokens</span>}{result.inputTruncated && <span className="text-sx-warn">Evidence was truncated to budget</span>}</div>
      {result.plan.length>0 && <div><h3 className="label">Agent plan</h3><ol className="mt-1 list-decimal space-y-1 pl-4 text-xs">{result.plan.map((p,i)=><li key={i}>{p}</li>)}</ol></div>}
      {result.evidenceAssessment && (
        <div className="rounded border border-sx-line p-2 text-[10px] text-sx-mute">
          <h3 className="label">Evidence review</h3>
          <p className="mt-1">Consistent: {result.evidenceAssessment.consistent} · Partial: {result.evidenceAssessment.partial} · Unverified: {result.evidenceAssessment.unverified}</p>
          <p className="mt-1">{result.evidenceAssessment.method}</p>
        </div>
      )}
      {result.steps.length > 0 && (
        <div>
          <h3 className="label">Collected evidence & verification</h3>
          <div className="mt-1 space-y-2">
            {result.steps.map(step => (
              <details key={step.step} className="rounded border border-sx-line p-2">
                <summary className="cursor-pointer text-xs">{step.step}. {step.tool} — {step.rationale} · {step.verification?.status || "unverified"} · {step.attempts || 1} attempt(s)</summary>
                <p className="mt-2 text-[10px] text-sx-mute">{step.verification?.summary || "No evidence review returned."}</p>
                {step.verification?.supportedFindings?.length ? <p className="mt-1 text-[10px]">Supported: {step.verification.supportedFindings.join("; ")}</p> : null}
                {step.verification?.gaps?.length ? <p className="mt-1 text-[10px] text-sx-warn">Gaps: {step.verification.gaps.join("; ")}</p> : null}
                {step.verification?.contradictions?.length ? <p className="mt-1 text-[10px] text-sx-red">Contradictions: {step.verification.contradictions.join("; ")}</p> : null}
                <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-words text-[10px] text-sx-mute">{JSON.stringify(step.result, null, 2)}</pre>
              </details>
            ))}
          </div>
        </div>
      )}
      <div><h3 className="label">Conclusion</h3><p className="mt-1 whitespace-pre-wrap text-xs leading-5">{result.conclusion}</p></div>
      <p className="text-[10px] text-sx-mute">Every tool call is audit logged. Tool calls are read-only. Conclusions require analyst verification; no containment or remediation is executed.</p>
    </div>}
  </section>;
}
