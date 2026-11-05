import { useEffect, useState, type FormEvent } from "react";
import { apiGet, apiPost, isBackendConfigured } from "../../services/apiClient";

type ConfigResponse = {
  configured: boolean;
  provider?: string;
  model?: string;
  apiKeyPresent?: boolean;
  canManage?: boolean;
  maxInputTokens?: number;
};

const FIXED_MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free";

export function AIProviderSettings() {
  const [apiKey, setApiKey] = useState("");
  const [configured, setConfigured] = useState(false);
  const [canManage, setCanManage] = useState(false);
  const [maxInputTokens, setMaxInputTokens] = useState(6000);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!isBackendConfigured) return;
    apiGet<ConfigResponse>("/api/ai/config").then((c) => {
      setConfigured(c.configured);
      setCanManage(c.canManage === true);
      setMaxInputTokens(c.maxInputTokens || 6000);
    }).catch((e) => setError(e instanceof Error ? e.message : "Could not load platform AI settings."));
  }, []);

  const save = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true); setError(""); setMessage("");
    try {
      const result = await apiPost<{ saved: boolean; model: string; maxInputTokens: number }>("/api/ai/config", {
        apiKey,
        maxInputTokens,
      });
      setConfigured(true); setApiKey("");
      setMessage("Shared SentinelX model connection encrypted and saved. All customer workspaces now use the same fixed agent and model.");
      setMaxInputTokens(result.maxInputTokens);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not save OpenRouter settings."); }
    finally { setBusy(false); }
  };

  const test = async () => {
    setBusy(true); setError(""); setMessage("");
    try {
      const result = await apiPost<{ ok: boolean; message: string; preview?: string }>("/api/ai/test", {});
      if (!result.ok) throw new Error(result.message);
      setMessage(result.message + (result.preview ? " “" + result.preview + "”" : ""));
    } catch (e) { setError(e instanceof Error ? e.message : "Model connection test failed."); }
    finally { setBusy(false); }
  };

  return <section className="rounded-lg border border-sx-line bg-sx-bg p-4 space-y-3">
    <div>
      <h3 className="text-sm font-semibold text-sx-ink">SentinelX AI Engine</h3>
      <p className="mt-1 text-[11px] text-sx-mute">One centrally managed SentinelX SOC Investigator agent and one fixed model for every customer. Customers cannot select, replace or bring their own agent/model.</p>
    </div>
    {!isBackendConfigured && <p className="text-xs text-sx-warn">Connect the SentinelX backend to configure the platform model.</p>}
    <div className="rounded-lg border border-sx-line p-3 space-y-1">
      <div className="text-xs text-sx-mute">Fixed model</div>
      <div className="mono break-all text-sm text-sx-ink">{FIXED_MODEL}</div>
      <div className="text-[10px] text-sx-mute">Provider: OpenRouter · Free model · Shared platform connection · Read-only agent tools</div>
      <div className="text-[10px] text-sx-mute">{configured ? "Platform model API key is configured." : "Platform model API key is not configured yet."}</div>
    </div>
    {canManage ? <form onSubmit={save} className="space-y-3">
      <label className="block text-xs text-sx-mute">OpenRouter API key
        <input className="input mt-1" type="password" autoComplete="new-password" value={apiKey} onChange={e=>setApiKey(e.target.value)} placeholder={configured ? "Saved key hidden — enter a replacement, or leave blank" : "Paste platform OpenRouter API key"} disabled={busy} />
      </label>
      <label className="block text-xs text-sx-mute">Maximum evidence input budget (approx. tokens)
        <input className="input mt-1" type="number" min={1000} max={12000} step={500} value={maxInputTokens} onChange={e=>setMaxInputTokens(Math.max(1000,Math.min(12000,Number(e.target.value)||1000)))} disabled={busy}/>
      </label>
      <p className="text-[10px] text-sx-mute">OpenRouter free-tier model; usage is not billed, but free-tier availability and rate limits apply. API key is encrypted server-side using AES-GCM. Sensitive evidence masking is always enabled. The model and agent identity are fixed in the backend.</p>
      {error && <p role="alert" className="text-xs text-sx-red">{error}</p>}
      {message && <p role="status" className="text-xs text-sx-gold break-words">{message}</p>}
      <div className="flex flex-wrap gap-2">
        <button className="btn btn-primary btn-sm" type="submit" disabled={!isBackendConfigured || busy || (!configured && apiKey.trim().length < 20)}>{busy ? "Working…" : "Save shared model key"}</button>
        <button className="btn btn-sm" type="button" onClick={test} disabled={!isBackendConfigured || busy || !configured}>Test model connection</button>
      </div>
    </form> : <div className="space-y-2">
      <p className="text-[11px] text-sx-mute">Only an explicitly registered SentinelX platform administrator can change the shared API key. Workspace owners and customer admins can view connection status but cannot replace the platform model.</p>
      <p className="text-[10px] text-sx-mute">Model connection testing and API-key management are reserved for the platform administrator.</p>
    </div>}
  </section>;
}
