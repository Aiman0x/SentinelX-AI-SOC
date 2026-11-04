import { useState } from "react";
import { apiPost, isBackendConfigured } from "../../services/apiClient";

type AgentResult = {
  agent: string;
  plan: string[];
  steps: { step: number; tool: string; rationale: string; result: unknown }[];
  conclusion: string;
  provider: string;
  model: string;
  toolCalls: number;
  maxSteps: number;
  accessMode: string;
  estimatedInputTokens?: number;
  inputTokenBudget?: number;
  inputTruncated?: boolean;
};

const AGENT_NAME = "SentinelX SOC Investigator v1";

export function AgentInvestigationPanel() {
  const [prompt, setPrompt] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<AgentResult | null>(null);

  const run = async () => {
    setBusy(true); setError(""); setResult(null);
    try {
      const response = await apiPost<AgentResult>("/api/ai/agent", { prompt });
      setResult(response);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Agent investigation failed.");
    } finally { setBusy(false); }
  };

  return <section className="panel space-y-3 p-4">
    <div>
      <h2 className="text-sm font-semibold">Autonomous SOC Agent</h2>
      <p className="mt-1 text-[11px] text-sx-mute">{AGENT_NAME} is the single centrally trained SentinelX investigation agent. It plans the investigation, selects only tools connected to your account, collects read-only evidence and produces an evidence-backed conclusion.</p>
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
      <span className="text-[10px] text-sx-mute">Fixed agent · Fixed model · Read-only · Server hard limit: 5 tool calls</span>
    </div>
    {error && <p role="alert" className="text-xs text-sx-red">{error}</p>}
    {result && <div className="space-y-3 border-t border-sx-line pt-3">
      <div className="flex flex-wrap gap-2 text-[10px] text-sx-mute"><span>{result.agent || AGENT_NAME}</span><span>{result.provider} · {result.model}</span><span>{result.toolCalls}/{result.maxSteps} tool calls</span><span>{result.accessMode}</span>{result.estimatedInputTokens !== undefined && <span>~{result.estimatedInputTokens} input tokens</span>}{result.inputTruncated && <span className="text-sx-warn">Evidence was truncated to budget</span>}</div>
      {result.plan.length>0 && <div><h3 className="label">Agent plan</h3><ol className="mt-1 list-decimal space-y-1 pl-4 text-xs">{result.plan.map((p,i)=><li key={i}>{p}</li>)}</ol></div>}
      {result.steps.length>0 && <div><h3 className="label">Collected evidence</h3><div className="mt-1 space-y-2">{result.steps.map(step=><details key={step.step} className="rounded border border-sx-line p-2"><summary className="cursor-pointer text-xs">{step.step}. {step.tool} — {step.rationale}</summary><pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-words text-[10px] text-sx-mute">{JSON.stringify(step.result,null,2)}</pre></details>)}</div></div>}
      <div><h3 className="label">Conclusion</h3><p className="mt-1 whitespace-pre-wrap text-xs leading-5">{result.conclusion}</p></div>
      <p className="text-[10px] text-sx-mute">Every tool call is audit logged. Tool calls are read-only. Conclusions require analyst verification; no containment or remediation is executed.</p>
    </div>}
  </section>;
}
