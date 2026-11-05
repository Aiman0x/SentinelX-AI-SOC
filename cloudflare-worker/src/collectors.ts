import { currentUser } from "./auth";
import { handleMcpRoute } from "./mcp";

interface CollectorEnv {
  DB: D1Database;
  INTEGRATION_CONFIGS: KVNamespace;
  ALLOWED_ORIGIN: string;
  CONFIG_ENCRYPTION_KEY: string;
}
type CollectorActor = { id: string; role: string; organization_id: string };
const supported = new Set(["sysmon", "clamav", "yara", "suricata", "zeek"]);
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
});
const id = () => crypto.randomUUID();
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const sha = async (value: string) => b64(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
const allowedOrigin = (req: Request, env: CollectorEnv) => {
  const origin = req.headers.get("Origin") || "";
  return !origin || env.ALLOWED_ORIGIN.split(",").map(x => x.trim()).includes(origin);
};
async function readJson(req: Request, max = 32768): Promise<Record<string, unknown> | null> {
  const length = Number(req.headers.get("Content-Length"));
  if (Number.isFinite(length) && length > max) return null;
  const text = await req.text();
  if (text.length > max) return null;
  try { const value = JSON.parse(text); return value && typeof value === "object" && !Array.isArray(value) ? value : null; }
  catch { return null; }
}
async function admin(req: Request, env: CollectorEnv): Promise<CollectorActor | null> {
  const actor = await currentUser(req, env as Parameters<typeof currentUser>[1]);
  return actor && (actor.role === "owner" || actor.role === "admin") ? actor as CollectorActor : null;
}
async function createCollector(req: Request, env: CollectorEnv) {
  const actor = await admin(req, env);
  if (!actor) return json({ error: "Authentication required or admin permission missing" }, 403);
  const body = await readJson(req, 4096);
  const name = typeof body?.name === "string" ? body.name.trim().slice(0, 80) : "";
  const platform = typeof body?.platform === "string" ? body.platform : "";
  if (name.length < 2 || !["windows", "linux", "macos", "other"].includes(platform)) return json({ error: "A collector name and supported platform are required." }, 400);
  const collectorId = id();
  const token = "sxcol_" + collectorId.replace(/-/g, "") + "_" + b64(crypto.getRandomValues(new Uint8Array(32)));
  await env.DB.prepare("INSERT INTO host_collectors(id,org_id,name,platform,token_hash) VALUES(?,?,?,?,?)")
    .bind(collectorId, actor.organization_id, name, platform, await sha(token)).run();
  return json({ created: true, collector: { id: collectorId, name, platform, createdAt: new Date().toISOString(), lastSeenAt: null, status: "pending" }, token, warning: "Copy this token now. It will not be shown again." }, 201);
}
async function listCollectors(req: Request, env: CollectorEnv) {
  const actor = await currentUser(req, env as Parameters<typeof currentUser>[1]);
  if (!actor) return json({ error: "Authentication required" }, 401);
  const rows = await env.DB.prepare("SELECT id,name,platform,created_at,last_seen_at,revoked_at FROM host_collectors WHERE org_id=? ORDER BY created_at DESC")
    .bind(actor.organization_id).all<{id:string;name:string;platform:string;created_at:string;last_seen_at:string|null;revoked_at:string|null}>();
  return json({ collectors: rows.results.map(row => ({ id: row.id, name: row.name, platform: row.platform, createdAt: row.created_at, lastSeenAt: row.last_seen_at, status: row.revoked_at ? "revoked" : row.last_seen_at && Date.now() - Date.parse(row.last_seen_at) < 10 * 60_000 ? "online" : row.last_seen_at ? "stale" : "pending" })) });
}
async function revokeCollector(req: Request, env: CollectorEnv, collectorId: string) {
  const actor = await admin(req, env);
  if (!actor) return json({ error: "Authentication required or admin permission missing" }, 403);
  const result = await env.DB.prepare("UPDATE host_collectors SET revoked_at=? WHERE id=? AND org_id=? AND revoked_at IS NULL")
    .bind(new Date().toISOString(), collectorId, actor.organization_id).run();
  return result.meta.changes ? json({ revoked: true }) : json({ error: "Collector not found or already revoked" }, 404);
}

function decode64(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(normalized + "=".repeat((4 - normalized.length % 4) % 4)), c => c.charCodeAt(0));
}
async function decryptValues(envelopeText: string, secret: string, aad: string): Promise<Record<string, string>> {
  if (!/^[0-9a-fA-F]{64}$/.test(secret)) throw new Error("Encryption key unavailable");
  const keyBytes = Uint8Array.from(secret.match(/.{2}/g)!, x => parseInt(x, 16));
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const envelope = JSON.parse(envelopeText) as { iv: string; data: string };
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: decode64(envelope.iv), additionalData: new TextEncoder().encode(aad) }, key, decode64(envelope.data));
  return JSON.parse(new TextDecoder().decode(plain)) as Record<string, string>;
}
async function collectorConfig(req: Request, env: CollectorEnv) {
  const authorization = req.headers.get("Authorization") || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  if (token.length < 40 || token.length > 256) return json({ error: "Collector authentication required" }, 401);
  const row = await env.DB.prepare("SELECT id,org_id FROM host_collectors WHERE token_hash=? AND revoked_at IS NULL")
    .bind(await sha(token)).first<{id:string;org_id:string}>();
  if (!row) return json({ error: "Invalid or revoked collector token" }, 401);
  if (!env.CONFIG_ENCRYPTION_KEY) return json({ error: "Secure configuration is unavailable" }, 503);
  const config: Record<string, Record<string, string>> = {};
  for (const integrationId of supported) {
    const storageKey = row.org_id + ":" + integrationId;
    const encrypted = await env.INTEGRATION_CONFIGS.get(storageKey);
    if (!encrypted) continue;
    try {
      const values = await decryptValues(encrypted, env.CONFIG_ENCRYPTION_KEY, storageKey);
      const safe = Object.fromEntries(Object.entries(values).filter(([key]) => !/(password|secret|token|api.?key|private.?key|credential)/i.test(key)));
      config[integrationId] = safe;
    } catch { /* Ignore an unreadable config; do not leak its contents. */ }
  }
  return json({ config, fetchedAt: new Date().toISOString() });
}

async function receiveHeartbeat(req: Request, env: CollectorEnv) {
  const authorization = req.headers.get("Authorization") || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  if (token.length < 40 || token.length > 256) return json({ error: "Collector authentication required" }, 401);
  const row = await env.DB.prepare("SELECT id,org_id FROM host_collectors WHERE token_hash=? AND revoked_at IS NULL")
    .bind(await sha(token)).first<{id:string;org_id:string}>();
  if (!row) return json({ error: "Invalid or revoked collector token" }, 401);
  const body = await readJson(req, 32768);
  if (!body || !Array.isArray(body.results) || body.results.length > 10) return json({ error: "Invalid heartbeat payload" }, 400);
  const observedAt = typeof body.observedAt === "string" && Number.isFinite(Date.parse(body.observedAt)) ? new Date(body.observedAt).toISOString() : new Date().toISOString();
  const accepted: string[] = [];
  for (const item of body.results) {
    if (!item || typeof item !== "object") continue;
    const result = item as Record<string, unknown>;
    const integrationId = typeof result.integrationId === "string" ? result.integrationId : "";
    if (!supported.has(integrationId)) continue;
    const status = ["healthy", "degraded", "unhealthy", "not_installed", "unknown"].includes(String(result.status)) ? String(result.status) : "unknown";
    const checks = Array.isArray(result.checks) ? result.checks.slice(0, 12).map(check => {
      const c = check && typeof check === "object" ? check as Record<string, unknown> : {};
      return { name: String(c.name || "check").slice(0, 60), status: ["pass","fail","warn","unknown"].includes(String(c.status)) ? String(c.status) : "unknown", detail: String(c.detail || "").slice(0, 240) };
    }) : [];
    const health = { ok: status === "healthy", status, message: "Host collector reported " + status + ".", checkedAt: observedAt, sensorId: row.id, checks, version: typeof result.version === "string" ? result.version.slice(0, 80) : null, metrics: result.metrics && typeof result.metrics === "object" ? result.metrics : {} };
    await env.INTEGRATION_CONFIGS.put(row.org_id + ":" + integrationId + ":health", JSON.stringify(health));
    accepted.push(integrationId);
  }
  await env.DB.prepare("UPDATE host_collectors SET last_seen_at=? WHERE id=?").bind(new Date().toISOString(), row.id).run();
  return json({ accepted, collectorId: row.id, receivedAt: new Date().toISOString() });
}
function scrubSecrets(value: unknown, depth = 0): unknown {
  if (depth > 8) return "[depth-limited]";
  if (Array.isArray(value)) return value.slice(0, 100).map(item => scrubSecrets(item, depth + 1));
  if (!value || typeof value !== "object") return typeof value === "string" ? value.slice(0, 4000) : value;
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>).slice(0, 100)) {
    if (/(password|secret|token|api.?key|authorization|cookie|private.?key)/i.test(key)) continue;
    out[key.slice(0, 100)] = scrubSecrets(item, depth + 1);
  }
  return out;
}
async function receiveEvents(req: Request, env: CollectorEnv) {
  const authorization = req.headers.get("Authorization") || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  if (token.length < 40 || token.length > 256) return json({ error: "Collector authentication required" }, 401);
  const collector = await env.DB.prepare("SELECT id,org_id FROM host_collectors WHERE token_hash=? AND revoked_at IS NULL")
    .bind(await sha(token)).first<{id:string;org_id:string}>();
  if (!collector) return json({ error: "Invalid or revoked collector token" }, 401);
  const body = await readJson(req, 262144);
  const integrationId = typeof body?.integrationId === "string" ? body.integrationId : "";
  if (!["sysmon", "suricata", "zeek"].includes(integrationId)) return json({ error: "integrationId must be sysmon, suricata or zeek" }, 400);
  const events = Array.isArray(body?.events) ? body.events : [];
  if (events.length < 1 || events.length > 100) return json({ error: "Provide between 1 and 100 normalized events" }, 400);
  const entityType = integrationId + "_event";
  const statements: D1PreparedStatement[] = [];
  let accepted = 0;
  for (const raw of events) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
    const event = raw as Record<string, unknown>;
    const eventId = typeof event.eventId === "string" && event.eventId.trim() ? event.eventId.trim().slice(0, 180) : crypto.randomUUID();
    const observedAt = typeof event.observedAt === "string" && Number.isFinite(Date.parse(event.observedAt)) ? new Date(event.observedAt).toISOString() : new Date().toISOString();
    const safePayload = scrubSecrets(event.payload ?? event) as Record<string, unknown>;
    const payload = JSON.stringify({ integrationId, collectorId: collector.id, observedAt, eventId, event: safePayload });
    if (payload.length > 16000) continue;
    const id = crypto.randomUUID();
    statements.push(env.DB.prepare("INSERT INTO soc_records(id,org_id,entity_type,source_table,source_record_id,case_id,payload_json,created_at,updated_at) VALUES(?,?,?,?,?,NULL,?,?,?) ON CONFLICT(org_id,entity_type,source_table,source_record_id) DO UPDATE SET payload_json=excluded.payload_json,updated_at=excluded.updated_at")
      .bind(id, collector.org_id, entityType, "collector_events", collector.id + ":" + eventId, payload, observedAt, new Date().toISOString()));
    accepted++;
  }
  if (statements.length) await env.DB.batch(statements);
  await env.DB.prepare("UPDATE host_collectors SET last_seen_at=? WHERE id=?").bind(new Date().toISOString(), collector.id).run();
  return json({ accepted, received: events.length, integrationId, collectorId: collector.id, organizationScoped: true });
}



async function encryptBridgePayload(value: unknown, secret: string, aad: string): Promise<string> {
  if (!/^[0-9a-fA-F]{64}$/.test(secret)) throw new Error("Encryption key unavailable");
  const keyBytes = Uint8Array.from(secret.match(/.{2}/g)!, x => parseInt(x, 16));
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) }, key, new TextEncoder().encode(JSON.stringify(value)));
  return JSON.stringify({ iv: b64(iv), data: b64(new Uint8Array(cipher)) });
}
async function decryptBridgePayload(envelopeText: string, secret: string, aad: string): Promise<Record<string, unknown>> {
  if (!/^[0-9a-fA-F]{64}$/.test(secret)) throw new Error("Encryption key unavailable");
  const keyBytes = Uint8Array.from(secret.match(/.{2}/g)!, x => parseInt(x, 16));
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const envelope = JSON.parse(envelopeText) as { iv: string; data: string };
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: decode64(envelope.iv), additionalData: new TextEncoder().encode(aad) }, key, decode64(envelope.data));
  return JSON.parse(new TextDecoder().decode(plain)) as Record<string, unknown>;
}

async function createBridge(req: Request, env: CollectorEnv) {
  const actor = await admin(req, env);
  if (!actor) return json({ error: "Authentication required or admin permission missing" }, 403);
  const body = await readJson(req, 4096);
  const name = typeof body?.name === "string" ? body.name.trim().slice(0, 80) : "";
  const platform = typeof body?.platform === "string" ? body.platform : "";
  if (name.length < 2 || !["windows", "linux", "macos"].includes(platform)) return json({ error: "Bridge name and Windows/Linux/macOS platform are required." }, 400);
  const existing = await env.DB.prepare("SELECT id FROM host_collectors WHERE org_id=? AND bridge_enabled=1 AND revoked_at IS NULL LIMIT 1").bind(actor.organization_id).first<{id:string}>();
  if (existing) return json({ error: "This workspace already has a local bridge. Revoke it before enrolling a replacement; one bridge currently serves all private tools in the workspace." }, 409);
  const bridgeId = id();
  const token = "sxbridge_" + bridgeId.replace(/-/g, "") + "_" + b64(crypto.getRandomValues(new Uint8Array(32)));
  await env.DB.prepare("INSERT INTO host_collectors(id,org_id,name,platform,token_hash,bridge_enabled) VALUES(?,?,?,?,?,1)")
    .bind(bridgeId, actor.organization_id, name, platform, await sha(token)).run();
  await env.DB.prepare("INSERT INTO audit_logs(id,org_id,actor_id,actor_type,event_type,target_id,details,outcome) VALUES(?,?,?,?,?,?,?,?)")
    .bind(id(), actor.organization_id, actor.id, "Human Admin", "local_bridge_enrolled", bridgeId, JSON.stringify({ platform, name }), "Success").run();
  return json({ created: true, bridge: { id: bridgeId, name, platform, status: "pending", createdAt: new Date().toISOString() }, token, warning: "Copy this token now. It will not be shown again." }, 201);
}
async function listBridges(req: Request, env: CollectorEnv) {
  const actor = await currentUser(req, env as Parameters<typeof currentUser>[1]);
  if (!actor) return json({ error: "Authentication required" }, 401);
  const rows = await env.DB.prepare("SELECT id,name,platform,created_at,last_seen_at,revoked_at FROM host_collectors WHERE org_id=? AND bridge_enabled=1 ORDER BY created_at DESC")
    .bind(actor.organization_id).all<{id:string;name:string;platform:string;created_at:string;last_seen_at:string|null;revoked_at:string|null}>();
  return json({ bridges: rows.results.map(row => ({ id: row.id, name: row.name, platform: row.platform, createdAt: row.created_at, lastSeenAt: row.last_seen_at, status: row.revoked_at ? "revoked" : row.last_seen_at && Date.now() - Date.parse(row.last_seen_at) < 90_000 ? "online" : row.last_seen_at ? "offline" : "pending" })) });
}
async function revokeBridge(req: Request, env: CollectorEnv, bridgeId: string) {
  const actor = await admin(req, env);
  if (!actor) return json({ error: "Authentication required or admin permission missing" }, 403);
  const result = await env.DB.prepare("UPDATE host_collectors SET revoked_at=? WHERE id=? AND org_id=? AND bridge_enabled=1 AND revoked_at IS NULL")
    .bind(new Date().toISOString(), bridgeId, actor.organization_id).run();
  return result.meta.changes ? json({ revoked: true }) : json({ error: "Bridge not found or already revoked" }, 404);
}
async function bridgeAuth(req: Request, env: CollectorEnv) {
  const authorization = req.headers.get("Authorization") || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  if (token.length < 40 || token.length > 256) return null;
  return env.DB.prepare("SELECT id,org_id FROM host_collectors WHERE token_hash=? AND bridge_enabled=1 AND revoked_at IS NULL")
    .bind(await sha(token)).first<{id:string;org_id:string}>();
}
async function bridgePoll(req: Request, env: CollectorEnv) {
  const bridge = await bridgeAuth(req, env);
  if (!bridge) return json({ error: "Invalid or revoked bridge token" }, 401);
  await env.DB.prepare("UPDATE host_collectors SET last_seen_at=? WHERE id=?").bind(new Date().toISOString(), bridge.id).run();
  const task = await env.DB.prepare("SELECT id,connector_id,request_json FROM bridge_tasks WHERE collector_id=? AND status='queued' AND expires_at>? ORDER BY created_at LIMIT 1")
    .bind(bridge.id, new Date().toISOString()).first<{id:string;connector_id:string;request_json:string}>();
  if (!task) return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  const claimed = await env.DB.prepare("UPDATE bridge_tasks SET status='claimed',claimed_at=? WHERE id=? AND collector_id=? AND status='queued'")
    .bind(new Date().toISOString(), task.id, bridge.id).run();
  if (claimed.meta.changes !== 1) return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  let payload: Record<string, unknown> = {};
  try { payload = await decryptBridgePayload(task.request_json, env.CONFIG_ENCRYPTION_KEY, "bridge-task:"+task.id); } catch { return json({ error: "Bridge task could not be decrypted" }, 500); }
  return json({ task: { id: task.id, connectorId: task.connector_id, ...payload } });
}
async function bridgeResult(req: Request, env: CollectorEnv, taskId: string) {
  const bridge = await bridgeAuth(req, env);
  if (!bridge) return json({ error: "Invalid or revoked bridge token" }, 401);
  const body = await readJson(req, 1_048_576);
  if (!body || typeof body.ok !== "boolean" || typeof body.message !== "string") return json({ error: "A bounded bridge result is required" }, 400);
  const safe = await encryptBridgePayload({ ok: body.ok, message: body.message.slice(0, 500), data: scrubSecrets(body.data) }, env.CONFIG_ENCRYPTION_KEY, "bridge-result:"+taskId);
  const result = await env.DB.prepare("UPDATE bridge_tasks SET status=?,result_json=?,completed_at=? WHERE id=? AND collector_id=? AND status='claimed' AND expires_at>?")
    .bind(body.ok ? "completed" : "failed", safe, new Date().toISOString(), taskId, bridge.id, new Date().toISOString()).run();
  if (result.meta.changes !== 1) return json({ error: "Task is missing, expired or already completed" }, 409);
  await env.DB.prepare("UPDATE host_collectors SET last_seen_at=? WHERE id=?").bind(new Date().toISOString(), bridge.id).run();
  return json({ accepted: true });
}

export async function handleCollectorRoute(req: Request, env: CollectorEnv, path: string): Promise<Response | null> {
  if (path.startsWith("/api/mcp/")) return handleMcpRoute(req, env, path);
  if (!path.startsWith("/api/collectors") && !path.startsWith("/api/bridges") && !path.startsWith("/api/bridge/") && path !== "/api/collector/heartbeat" && path !== "/api/collector/config" && path !== "/api/collector/events") return null;
  if (!allowedOrigin(req, env)) return json({ error: "Origin not allowed" }, 403);
  if (path === "/api/bridges" && req.method === "POST") return createBridge(req, env);
  if (path === "/api/bridges" && req.method === "GET") return listBridges(req, env);
  if (path === "/api/bridge/poll" && req.method === "GET") return bridgePoll(req, env);
  const bridgeResultMatch = path.match(/^\/api\/bridge\/result\/([0-9a-f-]+)$/);
  if (bridgeResultMatch && req.method === "POST") return bridgeResult(req, env, bridgeResultMatch[1]);
  const bridgeDeleteMatch = path.match(/^\/api\/bridges\/([0-9a-f-]+)$/);
  if (bridgeDeleteMatch && req.method === "DELETE") return revokeBridge(req, env, bridgeDeleteMatch[1]);
  if (path === "/api/collectors" && req.method === "POST") return createCollector(req, env);
  if (path === "/api/collectors" && req.method === "GET") return listCollectors(req, env);
  if (path === "/api/collector/heartbeat" && req.method === "POST") return receiveHeartbeat(req, env);
  if (path === "/api/collector/events" && req.method === "POST") return receiveEvents(req, env);
  if (path === "/api/collector/config" && req.method === "GET") return collectorConfig(req, env);
  const match = path.match(/^\/api\/collectors\/([0-9a-f-]+)$/);
  if (match && req.method === "DELETE") return revokeCollector(req, env, match[1]);
  return json({ error: "Not found" }, 404);
}
