import { currentUser } from "./auth";

interface AIEnv {
  CONFIG_ENCRYPTION_KEY: string;
  INTEGRATION_CONFIGS: KVNamespace;
}
type ProviderConfig = {
  provider: "openai" | "anthropic" | "gemini" | "openai-compatible";
  model: string;
  apiKey: string;
  baseUrl?: string;
};
type AISettings = { primary: ProviderConfig; fallbacks: ProviderConfig[]; maskSensitiveData: boolean; maxInputTokens: number };

const enc = new TextEncoder();
function bytesToB64(bytes: Uint8Array): string {
  let raw = "";
  for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromB64(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(normalized + "=".repeat((4 - normalized.length % 4) % 4)), c => c.charCodeAt(0));
}
async function keyFor(secret: string, usage: KeyUsage[]) {
  if (!/^[0-9a-fA-F]{64}$/.test(secret)) throw new Error("Encryption is not configured");
  const raw = Uint8Array.from(secret.match(/.{2}/g)!, b => parseInt(b, 16));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, usage);
}
function storageKey(org: string) { return org + ":ai-provider:v1"; }
async function seal(config: AISettings, secret: string, org: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await keyFor(secret, ["encrypt"]);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(org + ":ai-provider:v1") }, key, enc.encode(JSON.stringify(config)));
  return JSON.stringify({ v: 1, iv: bytesToB64(iv), data: bytesToB64(new Uint8Array(data)) });
}
async function unseal(raw: string, secret: string, org: string): Promise<AISettings> {
  const envelope = JSON.parse(raw) as { v: number; iv: string; data: string };
  if (envelope.v !== 1) throw new Error("Unsupported encrypted configuration version");
  const key = await keyFor(secret, ["decrypt"]);
  const data = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(envelope.iv), additionalData: enc.encode(org + ":ai-provider:v1") }, key, fromB64(envelope.data));
  const decoded = JSON.parse(new TextDecoder().decode(data)) as AISettings | ProviderConfig;
  // Backward-compatible migration from the original single-provider format.
  if ("primary" in decoded) return decoded;
  return { primary: decoded, fallbacks: [], maskSensitiveData: true, maxInputTokens: 6000 };
}
function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
}
function validEndpoint(value: string): boolean {
  try {
    const u = new URL(value);
    if (u.protocol !== "https:" || u.username || u.password || u.search || u.hash) return false;
    const host = u.hostname.toLowerCase();
    if (host.includes(":") || /^\\d{1,3}(?:\\.\\d{1,3}){3}$/.test(host) || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") ||
        host === "127.0.0.1" || host === "::1" || /^10\./.test(host) ||
        /^192\.168\./.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
        host === "169.254.169.254" || host === "0.0.0.0") return false;
    return true;
  } catch { return false; }
}
function endpoint(config: ProviderConfig): string {
  if (config.provider === "anthropic") return "https://api.anthropic.com/v1/messages";
  if (config.provider === "gemini") return `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(config.model)}:generateContent`;
  if (config.provider === "openai") return "https://api.openai.com/v1/chat/completions";
  const base = config.baseUrl || "";
  if (!validEndpoint(base)) throw new Error("Custom endpoint must be a public HTTPS URL.");
  return base.replace(/\/$/, "") + (base.endsWith("/v1") ? "/chat/completions" : "/v1/chat/completions");
}
async function callModel(config: ProviderConfig, prompt: string, maxOutputTokens = 1200): Promise<string> {
  const url = endpoint(config);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);
  try {
    let response: Response;
    if (config.provider === "anthropic") {
      response = await fetch(url, { method: "POST", headers: { "x-api-key": config.apiKey, "anthropic-version": "2023-06-01", "content-type": "application/json" }, body: JSON.stringify({ model: config.model, max_tokens: maxOutputTokens, messages: [{ role: "user", content: prompt }] }), signal: controller.signal, redirect: "error" });
    } else if (config.provider === "gemini") {
      response = await fetch(url, { method: "POST", headers: { "content-type": "application/json", "x-goog-api-key": config.apiKey }, body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { maxOutputTokens } }), signal: controller.signal, redirect: "error" });
    } else {
      response = await fetch(url, { method: "POST", headers: { Authorization: "Bearer " + config.apiKey, "content-type": "application/json" }, body: JSON.stringify({ model: config.model, max_tokens: 128, messages: [{ role: "user", content: prompt }] }), signal: controller.signal, redirect: "error" });
    }
    if (!response.ok) {
      const status = response.status;
      if (status === 401 || status === 403) throw new Error("Provider rejected the API key or permissions (HTTP " + status + ").");
      if (status === 429) throw new Error("Provider rate limit or quota reached (HTTP 429).");
      throw new Error("Provider request failed (HTTP " + status + ").");
    }
    const payload = await response.json() as any;
    const text = config.provider === "anthropic" ? payload.content?.find((x: any) => x.type === "text")?.text :
      config.provider === "gemini" ? payload.candidates?.[0]?.content?.parts?.map((x: any) => x.text || "").join("") :
      payload.choices?.[0]?.message?.content;
    if (typeof text !== "string" || !text.trim()) throw new Error("Provider returned no text response.");
    return text;
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") throw new Error("Provider request timed out after 20 seconds.");
    throw error;
  } finally { clearTimeout(timeout); }
}


// Mask common secrets and direct identifiers before evidence leaves the SentinelX gateway.
function maskSensitive(text: string): string {
  return text
    .replace(/(api[_ -]?key|password|passwd|secret|access[_ -]?token|authorization)(\s*[:=]\s*)[^\s,;]+/gi, "$1$2[REDACTED]")
    .replace(/Bearer\s+[A-Za-z0-9._~+\/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[EMAIL]")
    .replace(/\b(?:\+?\d[\d .()\-]{7,}\d)\b/g, "[PHONE]");
}
function estimateTokens(text: string): number { return Math.ceil(text.length / 4); }
function fitPrompt(text: string, budget: number): { text: string; estimatedTokens: number; truncated: boolean } {
  const maxChars = Math.max(400, Math.min(24000, budget * 4));
  const truncated = text.length > maxChars;
  const fitted = truncated ? text.slice(0, maxChars) + "\n[Evidence truncated to the configured input-token budget.]" : text;
  return { text: fitted, estimatedTokens: estimateTokens(fitted), truncated };
}
async function runFailover(settings: AISettings, prompt: string): Promise<{ answer: string; provider: string; model: string; attempts: string[] }> {
  const chain = [settings.primary, ...settings.fallbacks].filter(Boolean);
  const attempts: string[] = [];
  let last: unknown;
  for (const config of chain) {
    try {
      const answer = await callModel(config, prompt);
      return { answer, provider: config.provider, model: config.model, attempts };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Provider failed";
      attempts.push(config.provider + "/" + config.model + ": " + message);
      last = error;
    }
  }
  throw new Error("All configured LLM providers failed. " + (last instanceof Error ? last.message : ""));
}
\nexport async function handleAIRoute(request: Request, env: AIEnv, path: string): Promise<Response | null> {
  if (!path.startsWith("/api/ai/")) return null;
  const actor = await currentUser(request, env);
  if (!actor) return json({ error: "Authentication required" }, 401);
  if (path !== "/api/ai/analyze" && actor.role !== "owner" && actor.role !== "admin") return json({ error: "Admin permission required" }, 403);
  if (!env.CONFIG_ENCRYPTION_KEY || !env.INTEGRATION_CONFIGS) return json({ error: "Encrypted provider storage is not configured." }, 503);
  const key = storageKey(actor.organization_id);
  if (path === "/api/ai/config" && request.method === "GET") {
    const raw = await env.INTEGRATION_CONFIGS.get(key);
    if (!raw) return json({ configured: false });
    try {
      const c = await unseal(raw, env.CONFIG_ENCRYPTION_KEY, actor.organization_id);
      return json({ configured: true, provider: c.primary.provider, model: c.primary.model, baseUrl: c.primary.provider === "openai-compatible" ? c.primary.baseUrl : undefined, apiKeyPresent: Boolean(c.primary.apiKey), apiKeyHint: c.primary.apiKey ? "••••••••" + c.primary.apiKey.slice(-4) : "", fallbacks: c.fallbacks.map(x => ({ provider: x.provider, model: x.model, configured: true })), maskSensitiveData: c.maskSensitiveData, maxInputTokens: c.maxInputTokens });
    } catch { return json({ error: "Saved AI provider configuration could not be decrypted." }, 500); }
  }
  if (path === "/api/ai/config" && request.method === "POST") {
    let body: Record<string, unknown>;
    try { body = await request.json() as Record<string, unknown>; } catch { return json({ error: "Invalid JSON." }, 400); }
    const parseProvider = (item: any): ProviderConfig | null => {
      if (!item || !["openai", "anthropic", "gemini", "openai-compatible"].includes(String(item.provider))) return null;
      const model = typeof item.model === "string" ? item.model.trim() : "";
      const apiKey = typeof item.apiKey === "string" ? item.apiKey.trim() : "";
      const baseUrl = typeof item.baseUrl === "string" ? item.baseUrl.trim() : "";
      if (!model || model.length > 160 || apiKey.length < 8 || apiKey.length > 2048) return null;
      if (item.provider === "openai-compatible" && !validEndpoint(baseUrl)) return null;
      return { provider: item.provider, model, apiKey, ...(item.provider === "openai-compatible" ? { baseUrl } : {}) };
    };
    const primary = parseProvider(body);
    const fallbacksRaw = Array.isArray(body.fallbacks) ? body.fallbacks : [];
    const fallbacks = fallbacksRaw.slice(0, 3).map(parseProvider);
    if (!primary || fallbacks.some(x => !x)) return json({ error: "Primary and fallback providers need valid provider, model and API key values. Maximum three fallbacks." }, 400);
    const maxInputTokens = Math.max(500, Math.min(12000, Number(body.maxInputTokens) || 6000));
    try {
      const config: AISettings = { primary, fallbacks: fallbacks as ProviderConfig[], maskSensitiveData: body.maskSensitiveData !== false, maxInputTokens };
      await env.INTEGRATION_CONFIGS.put(key, await seal(config, env.CONFIG_ENCRYPTION_KEY, actor.organization_id));
      return json({ saved: true, configured: true, provider: primary.provider, model: primary.model, fallbackCount: fallbacks.length, maskSensitiveData: config.maskSensitiveData, maxInputTokens });
    } catch { return json({ error: "Could not securely save AI provider configuration." }, 500); }
  }
  if (path === "/api/ai/test" && request.method === "POST") {
    const raw = await env.INTEGRATION_CONFIGS.get(key);
    if (!raw) return json({ ok: false, message: "Save an AI provider configuration first." }, 400);
    try {
      const config = await unseal(raw, env.CONFIG_ENCRYPTION_KEY, actor.organization_id);
      const result = await runFailover(config, "Reply with exactly: SentinelX provider connection successful.");
      const answer = result.answer;
      return json({ ok: true, message: "Provider authenticated and generated a response.", preview: answer.slice(0, 180), checkedAt: new Date().toISOString() });
    } catch (error) { return json({ ok: false, message: error instanceof Error ? error.message : "Provider test failed." }); }
  }
  if (path === "/api/ai/analyze" && request.method === "POST") {
    let body: { prompt?: unknown };
    try { body = await request.json() as typeof body; } catch { return json({ error: "Invalid JSON." }, 400); }
    if (typeof body.prompt !== "string" || !body.prompt.trim() || body.prompt.length > 12000) return json({ error: "Prompt must be 1–12000 characters." }, 400);
    const raw = await env.INTEGRATION_CONFIGS.get(key);
    if (!raw) return json({ error: "Configure an AI provider in Settings first." }, 400);
    try {
      const config = await unseal(raw, env.CONFIG_ENCRYPTION_KEY, actor.organization_id);
      const prompt = config.maskSensitiveData ? maskSensitive(body.prompt) : body.prompt;
      const bounded = fitPrompt(prompt, config.maxInputTokens);
      const result = await runFailover(config, "You are SentinelX, a defensive SOC analyst. Analyze only supplied evidence; separate facts from hypotheses and never claim an action was executed.\\n\\n" + bounded.text);
      return json({ answer: result.answer, provider: result.provider, model: result.model, attemptedFallbacks: result.attempts.length, estimatedInputTokens: bounded.estimatedTokens, inputTokenBudget: config.maxInputTokens, truncated: bounded.truncated, dataMasking: config.maskSensitiveData, generatedAt: new Date().toISOString() });
    } catch (error) { return json({ error: error instanceof Error ? error.message : "AI analysis failed." }, 502); }
  }
  return json({ error: "Method not allowed." }, 405);
}
