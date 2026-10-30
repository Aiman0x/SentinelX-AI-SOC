import { currentUser, handleAuthRoute } from "./auth";
export interface Env {
  ALLOWED_ORIGIN: string;
  DB: D1Database;
  BOOTSTRAP_SECRET: string;
  LOGIN_PASSWORD_HASH: string;
  SESSION_HMAC_SECRET: string;
  AP_BRIDGE_KEY: string;
  CONFIG_ENCRYPTION_KEY: string;
  INTEGRATION_CONFIGS: KVNamespace;
  LOGIN_RATE_LIMITER: { limit: (input: { key: string }) => Promise<{ success: boolean }> };
  AP_READ_DETECTION_FINDINGS_URL: string;
  AP_READ_INCIDENT_RECORDS_URL: string;
  AP_READ_INVESTIGATIONS_URL: string;
  AP_READ_EVIDENCE_REFERENCES_URL: string;
  AP_READ_AUDIT_LOGS_URL: string;
  AP_READ_ASSETS_URL: string;
  AP_READ_DETECTION_RULES_URL: string;
  AP_READ_SECURITY_INTEGRATIONS_URL: string;
}

const SESSION_COOKIE = "sx_session";
const SESSION_TTL_SECONDS = 4 * 60 * 60;
const PBKDF2_ITERATIONS_MIN = 100_000;
const PBKDF2_ITERATIONS_MAX = 1_000_000;

const ROUTES: Record<string, keyof Env> = {
  "/api/alerts": "AP_READ_DETECTION_FINDINGS_URL",
  "/api/cases": "AP_READ_INCIDENT_RECORDS_URL",
  "/api/investigations": "AP_READ_INVESTIGATIONS_URL",
  "/api/evidence": "AP_READ_EVIDENCE_REFERENCES_URL",
  "/api/audit": "AP_READ_AUDIT_LOGS_URL",
  "/api/assets": "AP_READ_ASSETS_URL",
  "/api/rules": "AP_READ_DETECTION_RULES_URL",
};


const INTEGRATION_FIELDS: Record<string, string[]> = {
  wazuh: ["apiUrl", "apiUser", "apiPassword"],
  sysmon: ["collector", "configVersion"],
  clamav: ["host", "port"],
  yara: ["rulesPath"],
  suricata: ["eveLog", "sensor"],
  zeek: ["logPath", "sensor"],
};
function hexToBytes(value: string): Uint8Array {
  if (!/^[0-9a-fA-F]{64}$/.test(value)) throw new Error("Invalid encryption key");
  return Uint8Array.from(value.match(/.{2}/g)!, (byte) => parseInt(byte, 16));
}
async function configCryptoKey(secret: string, usage: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", hexToBytes(secret), { name: "AES-GCM" }, false, usage);
}
async function encryptConfig(value: unknown, secret: string, integrationId: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await configCryptoKey(secret, ["encrypt"]);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(integrationId) }, key, new TextEncoder().encode(JSON.stringify(value)));
  return JSON.stringify({ iv: bytesToBase64Url(iv), data: bytesToBase64Url(new Uint8Array(cipher)) });
}
async function decryptConfig(value: string, secret: string, integrationId: string): Promise<Record<string, string>> {
  const envelope = JSON.parse(value) as { iv: string; data: string };
  const key = await configCryptoKey(secret, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64UrlToBytes(envelope.iv), additionalData: new TextEncoder().encode(integrationId) }, key, base64UrlToBytes(envelope.data));
  return JSON.parse(new TextDecoder().decode(plain)) as Record<string, string>;
}

async function readBodyLimited(request: Request, maxBytes: number): Promise<{ raw: string | null; tooLarge: boolean }> {
  const contentLength = Number(request.headers.get("Content-Length"));
  if (Number.isFinite(contentLength) && contentLength > maxBytes) return { raw: null, tooLarge: true };
  if (!request.body) return { raw: "", tooLarge: false };
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return { raw: null, tooLarge: true };
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return { raw: new TextDecoder().decode(bytes), tooLarge: false };
  } catch {
    return { raw: null, tooLarge: false };
  } finally {
    reader.releaseLock();
  }
}

function integrationConfigKey(organizationId: string, integrationId: string): string {
  return `${organizationId}:${integrationId}`;
}

async function handleIntegrationConfig(request: Request, env: Env, cors: HeadersInit, integrationId: string): Promise<Response> {
  if (!isAllowedOrigin(request.headers.get("Origin") ?? "", env)) return reply({ error: "Origin not allowed" }, 403, cors);
  const actor = await currentUser(request, env);
  if (!actor) return reply({ error: "Authentication required" }, 401, cors);
  if (actor.role !== "owner" && actor.role !== "admin") return reply({ error: "Admin permission required" }, 403, cors);
  const allowed = INTEGRATION_FIELDS[integrationId];
  if (!allowed) return reply({ error: "Unknown integration" }, 404, cors);
  if (!env.CONFIG_ENCRYPTION_KEY || !env.INTEGRATION_CONFIGS) return reply({ error: "Secure configuration storage is not configured" }, 503, cors);
  if (!request.headers.get("Content-Type")?.toLowerCase().startsWith("application/json")) return reply({ error: "JSON required" }, 415, cors);
  const bodyRead = await readBodyLimited(request, 8192);
  if (bodyRead.tooLarge) return reply({ error: "Request too large" }, 413, cors);
  if (bodyRead.raw === null) return reply({ error: "Invalid request body" }, 400, cors);
  const raw = bodyRead.raw;
  let body: Record<string, unknown>;
  try { body = JSON.parse(raw) as Record<string, unknown>; } catch { return reply({ error: "Invalid JSON" }, 400, cors); }
  const values = body.values;
  if (!values || typeof values !== "object" || Array.isArray(values)) return reply({ error: "Configuration values are required" }, 400, cors);
  const safe: Record<string, string> = {};
  for (const [key, value] of Object.entries(values as Record<string, unknown>)) {
    if (!allowed.includes(key)) return reply({ error: "Unsupported configuration field" }, 400, cors);
    if (typeof value !== "string" || value.length > 2048) return reply({ error: "Invalid configuration value" }, 400, cors);
    if (value.trim()) safe[key] = value.trim();
  }
  if (!Object.keys(safe).length) return reply({ error: "Enter at least one configuration value" }, 400, cors);
  try {
    const storageKey = integrationConfigKey(actor.organization_id, integrationId);
    const existingRaw = await env.INTEGRATION_CONFIGS.get(storageKey);
    const existing = existingRaw ? await decryptConfig(existingRaw, env.CONFIG_ENCRYPTION_KEY, storageKey) : {};
    const merged = { ...existing, ...safe };
    await env.INTEGRATION_CONFIGS.put(storageKey, await encryptConfig(merged, env.CONFIG_ENCRYPTION_KEY, storageKey));
    return reply({ saved: true, integrationId, configuredKeys: Object.keys(merged), savedAt: new Date().toISOString(), secretValuesHidden: true }, 200, cors);
  } catch {
    return reply({ error: "Could not securely save integration configuration" }, 500, cors);
  }
}
async function integrationConfigSummary(env: Env, organizationId: string): Promise<Record<string, { configured: boolean; values: Record<string, string>; keys: string[] }>> {
  const result: Record<string, { configured: boolean; values: Record<string, string>; keys: string[] }> = {};
  for (const id of Object.keys(INTEGRATION_FIELDS)) {
    try {
      const storageKey = integrationConfigKey(organizationId, id);
      const encrypted = await env.INTEGRATION_CONFIGS.get(storageKey);
      if (!encrypted || !env.CONFIG_ENCRYPTION_KEY) { result[id] = { configured: false, values: {}, keys: [] }; continue; }
      const values = await decryptConfig(encrypted, env.CONFIG_ENCRYPTION_KEY, storageKey);
      const publicValues = Object.fromEntries(Object.entries(values).filter(([key]) => !["webhookSecret", "apiPassword"].includes(key)));
      result[id] = { configured: true, values: publicValues, keys: Object.keys(values) };
    } catch { result[id] = { configured: false, values: {}, keys: [] }; }
  }
  return result;
}

const reply = (body: unknown, status: number, cors: HeadersInit = {}, extra: HeadersInit = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...cors,
      ...extra,
    },
  });

function isAllowedOrigin(origin: string, env: Env): boolean {
  return Boolean(origin) && env.ALLOWED_ORIGIN.split(",").map((value) => value.trim()).includes(origin);
}

function corsHeaders(origin: string, env: Env): HeadersInit {
  if (!isAllowedOrigin(origin, env)) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Accept, Content-Type, X-SentinelX-Bootstrap",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}
function getCookie(request: Request, name: string): string | null {
  const cookie = request.headers.get("Cookie") ?? "";
  for (const part of cookie.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return null;
}
function cookieHeader(value: string, maxAge: number): string {
  return `${SESSION_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  try {
    const [algorithm, iterationsText, saltText, hashText] = encoded.split("$");
    const iterations = Number(iterationsText);
    if (algorithm !== "pbkdf2-sha256" || !Number.isInteger(iterations) ||
        iterations < PBKDF2_ITERATIONS_MIN || iterations > PBKDF2_ITERATIONS_MAX) return false;
    const salt = base64UrlToBytes(saltText);
    const expected = base64UrlToBytes(hashText);
    if (salt.length < 16 || expected.length !== 32) return false;
    const material = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"],
    );
    const derived = new Uint8Array(await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations }, material, 256,
    ));
    return constantTimeEqual(derived, expected);
  } catch {
    return false;
  }
}

async function signSession(payload: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload)));
  return `${payload}.${bytesToBase64Url(signature)}`;
}

async function verifySession(request: Request, env: Env): Promise<boolean> {
  return (await currentUser(request, env)) !== null;
}

async function handleLogin(request: Request, env: Env, cors: HeadersInit): Promise<Response> {
  if (!isAllowedOrigin(request.headers.get("Origin") ?? "", env)) {
    return reply({ error: "Origin not allowed" }, 403, cors);
  }
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const rate = await env.LOGIN_RATE_LIMITER.limit({ key: ip });
  if (!rate.success) return reply({ error: "Too many login attempts. Try again in one minute." }, 429, cors);
  if (!env.LOGIN_PASSWORD_HASH || !env.SESSION_HMAC_SECRET) {
    return reply({ error: "Authentication is not configured" }, 503, cors);
  }
  if (!request.headers.get("Content-Type")?.toLowerCase().startsWith("application/json")) {
    return reply({ error: "JSON required" }, 415, cors);
  }
  const bodyRead = await readBodyLimited(request, 4096);
  if (bodyRead.tooLarge) return reply({ error: "Request too large" }, 413, cors);
  if (bodyRead.raw === null) return reply({ error: "Invalid request body" }, 400, cors);
  const raw = bodyRead.raw;
  let body: { password?: unknown };
  try { body = JSON.parse(raw) as { password?: unknown }; }
  catch { return reply({ error: "Invalid JSON" }, 400, cors); }
  if (typeof body.password !== "string" || body.password.length < 1 || body.password.length > 256) {
    return reply({ error: "Invalid credentials" }, 401, cors);
  }
  if (!(await verifyPassword(body.password, env.LOGIN_PASSWORD_HASH))) {
    return reply({ error: "Invalid credentials" }, 401, cors);
  }
  const now = Math.floor(Date.now() / 1000);
  const claims = bytesToBase64Url(new TextEncoder().encode(JSON.stringify({
    iat: now, exp: now + SESSION_TTL_SECONDS,
  })));
  const token = await signSession(claims, env.SESSION_HMAC_SECRET);
  return reply({ authenticated: true, expiresIn: SESSION_TTL_SECONDS }, 200, cors, {
    "Set-Cookie": cookieHeader(token, SESSION_TTL_SECONDS),
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") ?? "";
    const cors = corsHeaders(origin, env);

    if (request.method === "OPTIONS") {
      return isAllowedOrigin(origin, env)
        ? new Response(null, { status: 204, headers: cors })
        : reply({ error: "Origin not allowed" }, 403);
    }
    if (origin && !isAllowedOrigin(origin, env)) return reply({ error: "Origin not allowed" }, 403);

    const authResponse = await handleAuthRoute(request, env, url.pathname);
    if (authResponse) return new Response(authResponse.body, { status: authResponse.status, headers: { ...Object.fromEntries(authResponse.headers), ...cors } });

    if (url.pathname === "/api/auth/login" && request.method === "POST") {
      return handleLogin(request, env, cors);
    }
    if (url.pathname === "/api/auth/logout" && request.method === "POST") {
      if (!isAllowedOrigin(origin, env)) return reply({ error: "Origin not allowed" }, 403, cors);
      return reply({ authenticated: false }, 200, cors, { "Set-Cookie": cookieHeader("", 0) });
    }
    if (url.pathname === "/api/auth/me" && request.method === "GET") {
      const authenticated = await verifySession(request, env);
      return reply({ authenticated }, authenticated ? 200 : 401, cors);
    }

    const configMatch = url.pathname.match(/^\/api\/integrations\/([a-z0-9_-]+)\/config$/);
    if (configMatch && request.method === "POST") {
      return handleIntegrationConfig(request, env, cors, configMatch[1]);
    }
    if (url.pathname.startsWith("/api/integrations/") && url.pathname.endsWith("/test") && request.method === "POST") {
      const actor = await currentUser(request, env);
      if (!actor) return reply({ error: "Authentication required" }, 401, cors);
      if (actor.role !== "owner" && actor.role !== "admin") return reply({ error: "Admin permission required" }, 403, cors);
      return reply({ ok: false, unavailable: true, message: "Connection testing will be enabled after the tool-specific Activepieces adapters are configured." }, 501, cors);
    }

    if (request.method !== "GET") return reply({ error: "Method not allowed" }, 405, cors);
    const envKey = ROUTES[url.pathname];
    if (!envKey) return reply({ error: "Not found" }, 404, cors);

    const actor = await currentUser(request, env);
    if (!actor) {
      return reply({ error: "Authentication required" }, 401, cors);
    }
    if (url.pathname === "/api/integrations") {
      const actor = await currentUser(request, env);
      if (!actor) return reply({ error: "Authentication required" }, 401, cors);
      return reply({ data: [], configs: await integrationConfigSummary(env, actor.organization_id) }, 200, cors);
    }

    const webhookUrl = env[envKey];
    if (typeof webhookUrl !== "string" || !webhookUrl || !env.AP_BRIDGE_KEY) {
      return reply({ error: "Backend route is not configured" }, 503, cors);
    }
    try {
      const upstream = await fetch(webhookUrl, {
        method: "GET",
        headers: { Accept: "application/json", "X-SentinelX-Bridge-Key": env.AP_BRIDGE_KEY },
        redirect: "error",
      });
      const raw = await upstream.text();
      if (!upstream.ok) return reply({ error: "Upstream workflow failed", upstreamStatus: upstream.status }, 502, cors);
      let payload: unknown;
      try { payload = raw ? JSON.parse(raw) : null; }
      catch { return reply({ error: "Upstream returned invalid JSON" }, 502, cors); }
      if (payload && typeof payload === "object" && "data" in payload) {
        payload = (payload as { data: unknown }).data;
      }
      if (url.pathname === "/api/integrations") {
        return reply({ data: payload, configs: await integrationConfigSummary(env, actor.organization_id) }, 200, cors);
      }
      return reply(payload, 200, cors);
    } catch {
      return reply({ error: "Could not reach upstream workflow" }, 502, cors);
    }
  },
};
