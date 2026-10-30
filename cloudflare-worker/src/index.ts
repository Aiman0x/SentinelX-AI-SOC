export interface Env {
  ALLOWED_ORIGIN: string;
  LOGIN_PASSWORD_HASH: string;
  SESSION_HMAC_SECRET: string;
  AP_BRIDGE_KEY: string;
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
  "/api/integrations": "AP_READ_SECURITY_INTEGRATIONS_URL",
};

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

function corsHeaders(origin: string, env: Env): HeadersInit {
  if (!origin || origin !== env.ALLOWED_ORIGIN) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Accept, Content-Type",
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
  return `${SESSION_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=None; Partitioned`;
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

async function verifySession(request: Request, secret: string): Promise<boolean> {
  if (!secret) return false;
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return false;
  try {
    const separator = token.lastIndexOf(".");
    if (separator < 1) return false;
    const payload = token.slice(0, separator);
    const signature = base64UrlToBytes(token.slice(separator + 1));
    const key = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"],
    );
    const valid = await crypto.subtle.verify(
      "HMAC", key, signature, new TextEncoder().encode(payload),
    );
    if (!valid) return false;
    const claims = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payload))) as { exp?: number; iat?: number };
    const now = Math.floor(Date.now() / 1000);
    return Number.isInteger(claims.exp) && Number.isInteger(claims.iat) &&
      (claims.exp as number) > now && (claims.exp as number) - (claims.iat as number) <= SESSION_TTL_SECONDS;
  } catch {
    return false;
  }
}

async function handleLogin(request: Request, env: Env, cors: HeadersInit): Promise<Response> {
  if (request.headers.get("Origin") !== env.ALLOWED_ORIGIN) {
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
  const length = Number(request.headers.get("Content-Length") ?? "0");
  if (length > 4096) return reply({ error: "Request too large" }, 413, cors);
  let body: { password?: unknown };
  try { body = await request.json() as { password?: unknown }; }
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
      return origin === env.ALLOWED_ORIGIN
        ? new Response(null, { status: 204, headers: cors })
        : reply({ error: "Origin not allowed" }, 403);
    }
    if (origin && origin !== env.ALLOWED_ORIGIN) return reply({ error: "Origin not allowed" }, 403);

    if (url.pathname === "/api/auth/login" && request.method === "POST") {
      return handleLogin(request, env, cors);
    }
    if (url.pathname === "/api/auth/logout" && request.method === "POST") {
      if (origin !== env.ALLOWED_ORIGIN) return reply({ error: "Origin not allowed" }, 403, cors);
      return reply({ authenticated: false }, 200, cors, { "Set-Cookie": cookieHeader("", 0) });
    }
    if (url.pathname === "/api/auth/me" && request.method === "GET") {
      const authenticated = await verifySession(request, env.SESSION_HMAC_SECRET);
      return reply({ authenticated }, authenticated ? 200 : 401, cors);
    }

    if (request.method !== "GET") return reply({ error: "Method not allowed" }, 405, cors);
    const envKey = ROUTES[url.pathname];
    if (!envKey) return reply({ error: "Not found" }, 404, cors);

    if (!(await verifySession(request, env.SESSION_HMAC_SECRET))) {
      return reply({ error: "Authentication required" }, 401, cors);
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
      return reply(payload, 200, cors);
    } catch {
      return reply({ error: "Could not reach upstream workflow" }, 502, cors);
    }
  },
};
