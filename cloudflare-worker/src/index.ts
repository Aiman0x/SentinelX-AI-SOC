export interface Env {
  ALLOWED_ORIGIN: string;
  CF_ACCESS_TEAM_DOMAIN: string;
  CF_ACCESS_AUD: string;
  AP_BRIDGE_KEY: string;
  AP_READ_DETECTION_FINDINGS_URL: string;
  AP_READ_INCIDENT_RECORDS_URL: string;
  AP_READ_INVESTIGATIONS_URL: string;
  AP_READ_EVIDENCE_REFERENCES_URL: string;
  AP_READ_AUDIT_LOGS_URL: string;
  AP_READ_ASSETS_URL: string;
  AP_READ_DETECTION_RULES_URL: string;
  AP_READ_SECURITY_INTEGRATIONS_URL: string;
}

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

const reply = (body: unknown, status: number, cors: HeadersInit = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...cors },
  });

function corsHeaders(origin: string, env: Env): HeadersInit {
  if (!origin || origin !== env.ALLOWED_ORIGIN) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Accept, Content-Type",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

function decodePart(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}
function decodeJson<T>(value: string): T {
  return JSON.parse(new TextDecoder().decode(decodePart(value))) as T;
}

async function verifyAccessJwt(request: Request, env: Env): Promise<boolean> {
  if (!env.CF_ACCESS_TEAM_DOMAIN || !env.CF_ACCESS_AUD) return false;
  const token = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!token) return false;
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const header = decodeJson<{ kid?: string; alg?: string }>(parts[0]);
    const claims = decodeJson<{ aud?: string | string[]; exp?: number; nbf?: number; iss?: string }>(parts[1]);
    if (header.alg !== "RS256" || !header.kid) return false;
    const team = env.CF_ACCESS_TEAM_DOMAIN.replace(/^https?:\/\//, "").replace(/\/$/, "");
    const issuer = "https://" + team;
    if (claims.iss !== issuer || !claims.exp || claims.exp <= Date.now() / 1000) return false;
    if (claims.nbf && claims.nbf > Date.now() / 1000) return false;
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audiences.includes(env.CF_ACCESS_AUD)) return false;
    const certResponse = await fetch(issuer + "/cdn-cgi/access/certs");
    if (!certResponse.ok) return false;
    const certs = await certResponse.json() as { keys?: JsonWebKey[] };
    const jwk = certs.keys?.find((key) => key.kid === header.kid);
    if (!jwk) return false;
    const key = await crypto.subtle.importKey("jwk", jwk, {
      name: "RSASSA-PKCS1-v1_5", hash: "SHA-256",
    }, false, ["verify"]);
    return crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5", key, decodePart(parts[2]),
      new TextEncoder().encode(parts[0] + "." + parts[1]),
    );
  } catch {
    return false;
  }
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
    if (url.pathname === "/health" && request.method === "GET") {
      return reply({ ok: true, service: "sentinelx-api-gateway", mode: "read-only" }, 200, cors);
    }
    if (request.method !== "GET") return reply({ error: "Method not allowed" }, 405, cors);
    const envKey = ROUTES[url.pathname];
    if (!envKey) return reply({ error: "Not found" }, 404, cors);

    // Fail closed: protect this Worker with Cloudflare Access and validate its JWT.
    if (!(await verifyAccessJwt(request, env))) return reply({ error: "Authentication required" }, 401, cors);

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
