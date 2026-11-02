import { useEffect, useState, type FormEvent } from "react";
import { apiGet, apiPost, isBackendConfigured } from "../../services/apiClient";

type Provider = "openai" | "anthropic" | "gemini" | "openai-compatible";
type ConfigResponse = { configured: boolean; provider?: Provider; model?: string; baseUrl?: string; apiKeyPresent?: boolean; apiKeyHint?: string; fallbacks?: { provider: Provider; model: string }[]; maskSensitiveData?: boolean; maxInputTokens?: number };
const defaults: Record<Provider, string> = {
  openai: "gpt-4o-mini",
  anthropic: "claude-3-5-haiku-latest",
  gemini: "gemini-2.5-flash",
  "openai-compatible": "your-model-name",
};

export function AIProviderSettings() {
  const [provider, setProvider] = useState<Provider>("openai");
  const [model, setModel] = useState(defaults.openai);
  const [apiKey, setApiKey] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [configured, setConfigured] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [hint, setHint] = useState("");
  const [fallbackProvider, setFallbackProvider] = useState<Provider>("anthropic");
  const [fallbackModel, setFallbackModel] = useState("claude-3-5-haiku-latest");
  const [fallbackKey, setFallbackKey] = useState("");
  const [maskSensitiveData, setMaskSensitiveData] = useState(true);
  const [maxInputTokens, setMaxInputTokens] = useState(6000);
  const [fallbackConfigured, setFallbackConfigured] = useState(false);

  useEffect(() => {
    if (!isBackendConfigured) return;
    apiGet<ConfigResponse>("/api/ai/config").then((c) => {
      setConfigured(c.configured);
      if (c.provider) setProvider(c.provider);
      if (c.model) setModel(c.model);
      if (c.baseUrl) setBaseUrl(c.baseUrl);
      if (c.apiKeyHint) setHint(c.apiKeyHint);
      setMaskSensitiveData(c.maskSensitiveData !== false);
      setMaxInputTokens(c.maxInputTokens || 6000);
      if (c.fallbacks?.[0]) { setFallbackProvider(c.fallbacks[0].provider); setFallbackModel(c.fallbacks[0].model); setFallbackConfigured(true); }
    }).catch((e) => setError(e instanceof Error ? e.message : "Could not load AI provider."));
  }, []);

  const save = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setError(""); setMessage("");
    try {
      await apiPost("/api/ai/config", { provider, model, apiKey, ...(provider === "openai-compatible" ? { baseUrl } : {}), fallbacks: fallbackKey.trim().length >= 8 ? [{ provider: fallbackProvider, model: fallbackModel, apiKey: fallbackKey }] : [], maskSensitiveData, maxInputTokens });
      setConfigured(true); setHint("••••••••" + apiKey.slice(-4)); setApiKey(""); if (fallbackKey) { setFallbackConfigured(true); setFallbackKey(""); }
      setMessage("Provider settings encrypted and saved for this workspace.");
    } catch (e) { setError(e instanceof Error ? e.message : "Could not save provider."); }
    finally { setBusy(false); }
  };
  const test = async () => {
    setBusy(true); setError(""); setMessage("");
    try {
      const result = await apiPost<{ ok: boolean; message: string; preview?: string }>("/api/ai/test", {});
      if (!result.ok) throw new Error(result.message);
      setMessage(result.message + (result.preview ? " “" + result.preview + "”" : ""));
    } catch (e) { setError(e instanceof Error ? e.message : "Provider test failed."); }
    finally { setBusy(false); }
  };

  return <section className="rounded-lg border border-sx-line bg-sx-bg p-4 space-y-3">
    <div><h3 className="text-sm font-semibold text-sx-ink">Bring Your Own LLM (BYO-LLM)</h3>
      <p className="mt-1 text-[11px] text-sx-mute">Connect your own AI provider. The API key is sent directly to the SentinelX backend and encrypted per workspace; it is never saved in browser storage.</p></div>
    {!isBackendConfigured && <p className="text-xs text-sx-warn">Connect the SentinelX backend to configure a provider. Demo mode cannot store or test API keys.</p>}
    <form onSubmit={save} className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="block text-xs text-sx-mute">Provider
          <select className="input mt-1" value={provider} disabled={!isBackendConfigured || busy} onChange={(e) => { const p=e.target.value as Provider; setProvider(p); setModel(defaults[p]); }}>
            <option value="openai">OpenAI</option><option value="anthropic">Anthropic (Claude)</option><option value="gemini">Google Gemini</option><option value="openai-compatible">OpenAI-compatible / Self-hosted</option>
          </select>
        </label>
        <label className="block text-xs text-sx-mute">Model
          <input className="input mt-1" value={model} onChange={(e)=>setModel(e.target.value)} maxLength={160} required disabled={!isBackendConfigured || busy} placeholder={defaults[provider]} />
        </label>
      </div>
      {provider === "openai-compatible" && <label className="block text-xs text-sx-mute">Custom HTTPS API base URL
        <input className="input mt-1" type="url" value={baseUrl} onChange={(e)=>setBaseUrl(e.target.value)} required placeholder="https://your-llm.example.com/v1" disabled={busy || !isBackendConfigured} />
      </label>}
      <label className="block text-xs text-sx-mute">API key
        <input className="input mt-1" type="password" autoComplete="new-password" value={apiKey} onChange={(e)=>setApiKey(e.target.value)} required placeholder={configured ? "Saved key hidden — enter a new key to replace it" : "Paste your provider API key"} disabled={!isBackendConfigured || busy} />
      </label>
      <div className="rounded-lg border border-sx-line p-3 space-y-2">
        <div className="text-xs font-semibold text-sx-ink">Failover provider (optional)</div>
        <p className="text-[10px] text-sx-mute">If the primary provider fails or reaches quota, SentinelX tries this backup.</p>
        <div className="grid gap-2 sm:grid-cols-2">
          <select className="input" value={fallbackProvider} onChange={e=>{const p=e.target.value as Provider;setFallbackProvider(p);setFallbackModel(defaults[p]);}} disabled={!isBackendConfigured||busy}><option value="openai">OpenAI</option><option value="anthropic">Anthropic</option><option value="gemini">Gemini</option><option value="openai-compatible">OpenAI-compatible</option></select>
          <input className="input" value={fallbackModel} onChange={e=>setFallbackModel(e.target.value)} placeholder="Fallback model" maxLength={160} disabled={!isBackendConfigured||busy}/>
        </div>
        <input className="input" type="password" autoComplete="new-password" value={fallbackKey} onChange={e=>setFallbackKey(e.target.value)} placeholder={fallbackConfigured ? "Saved fallback key hidden — enter replacement" : "Fallback API key (optional)"} disabled={!isBackendConfigured||busy}/>
      </div>
      <div className="rounded-lg border border-sx-line p-3 space-y-3">
        <div className="text-xs font-semibold text-sx-ink">Privacy & token controls</div>
        <label className="flex items-start gap-2 text-xs"><input type="checkbox" checked={maskSensitiveData} onChange={e=>setMaskSensitiveData(e.target.checked)} className="mt-0.5"/> <span>Mask common secrets, email addresses and phone numbers before sending evidence to an LLM.</span></label>
        <label className="block text-xs text-sx-mute">Maximum input budget (approx. tokens)
          <input className="input mt-1" type="number" min={500} max={12000} step={500} value={maxInputTokens} onChange={e=>setMaxInputTokens(Math.max(500,Math.min(12000,Number(e.target.value)||500)))} disabled={busy}/>
        </label>
      </div>
      {configured && <p className="text-[10px] text-sx-ok">Provider configured · {provider} · {model} {hint && "· " + hint}</p>}
      {error && <p role="alert" className="text-xs text-sx-red">{error}</p>}
      {message && <p role="status" className="text-xs text-sx-gold break-words">{message}</p>}
      <div className="flex flex-wrap gap-2">
        <button className="btn btn-primary btn-sm" type="submit" disabled={!isBackendConfigured || busy || !model.trim() || apiKey.trim().length < 8}>{busy ? "Working…" : "Save provider"}</button>
        <button className="btn btn-sm" type="button" onClick={test} disabled={!isBackendConfigured || busy || !configured}>Test connection</button>
      </div>
    </form>
    <p className="text-[10px] text-sx-mute">Supported adapters: OpenAI Chat Completions, Anthropic Messages, Gemini generateContent, and OpenAI-compatible HTTPS endpoints. Provider usage and billing are handled by your provider account. Input tokens are estimated from text length; masking is best-effort, not guaranteed anonymization.</p>
  </section>;
}
