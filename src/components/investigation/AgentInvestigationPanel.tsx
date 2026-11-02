import { useState } from "react";
import { apiPost, isBackendConfigured } from "../../services/apiClient";

type AgentResult = {
  plan: string[];
  steps: { step: number; tool: string; rationale: string; result: unknown }[];
  conclusion: string;
  provider: string;
  model: string;
  toolCalls: number;
  maxSteps: number;
  accessMode: string;
};

export function AgentInvestigationPanel() {
  const [prompt, setPrompt] = useState("");
  const [maxSteps, setMaxSteps] = useState(5);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<AgentResult | null>(null);

  const run = async () => {
    setBusy(true); setError(""); setResult(null);
    try {
      const response = await apiPost<AgentResult>("/api/ai/agent", { prompt, maxSteps });
      setResult(response);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Agent investigation failed.");
    } finally { setBusy(false); }
  };

  return <section className="panel space-y-3 p-4">
    <div>
      <h2 className="text-sm font-semibold">Autonomous SOC Agent</h2>
      <p className="mt-1 text-[11px] text-sx-mute">The agent plans an investigation, chooses only tools connected to your user account, collects read-only evidence and writes a conclusion. Every connector query is audited.</p>
    </div>
    {!isBackendConfigured && <p className="text-xs text-sx-warn">Connect the SentinelX backend to run the agent.</p>}
    <label className="block text-xs text-sx-mute">Investigation task
      <textarea className="input mt-1 min-h-24 w-full" value={prompt} onChange={e=>setPrompt(e.target.value)} maxLength={12000} placeholder="Investigate this alert or indicator. Identify suspicious activity, gather relevant evidence from my connected tools, and explain the likely cause and defensive next steps." disabled={busy}/>
    </label>
    <div className="flex flex-wrap items-end gap-3">
      <label className="block text-xs text-sx-mute">Maximum tool calls
        <select className="input mt-1" value={maxSteps} onChange={e=>setMaxSteps(Number(e.target.value))} disabled={busy}>
          {[1,2,3,4,5].map(n=><option key={n} value={n}>{n} steps</option>)}
        </select>
      </label>
      <button className="btn btn-primary btn-sm" onClick={run} disabled={!isBackendConfigured||busy||!prompt.trim()}>{busy ? "Investigating…" : "Run agent investigation"}</button>
      <span className="text-[10px] text-sx-mute">Read-only · hard limit 5 tool calls</span>
    </div>
    {error && <p role="alert" className="text-xs text-sx-red">{error}</p>}
    {result && <div className="space-y-3 border-t border-sx-line pt-3">
      <div className="flex flex-wrap gap-2 text-[10px] text-sx-mute"><span>{result.provider} · {result.model}</span><span>{result.toolCalls}/{result.maxSteps} tool calls</span><span>{result.accessMode}</span></div>
      {result.plan.length>0 && <div><h3 className="label">Agent plan</h3><ol className="mt-1 list-decimal space-y-1 pl-4 text-xs">{result.plan.map((p,i)=><li key={i}>{p}</li>)}</ol></div>}
      {result.steps.length>0 && <div><h3 className="label">Collected evidence</h3><div className="mt-1 space-y-2">{result.steps.map(step=><details key={step.step} className="rounded border border-sx-line p-2"><summary className="cursor-pointer text-xs">{step.step}. {step.tool} — {step.rationale}</summary><pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-words text-[10px] text-sx-mute">{JSON.stringify(step.result,null,2)}</pre></details>)}</div></div>}
      <div><h3 className="label">Conclusion</h3><p className="mt-1 whitespace-pre-wrap text-xs leading-5">{result.conclusion}</p></div>
      <p className="text-[10px] text-sx-mute">Tool calls are read-only. Conclusions are AI-generated and require analyst verification; no containment or remediation was executed.</p>
    </div>}
  </section>;
}
