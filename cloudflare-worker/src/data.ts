import { currentUser } from "./auth";

interface DataEnv { DB: D1Database; ALLOWED_ORIGIN: string; AP_BRIDGE_KEY: string; }
type Actor = { id: string; role: string; organization_id: string; email: string; display_name: string };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
});
const uid = () => crypto.randomUUID();
const iso = () => new Date().toISOString();
const allowedOrigin = (request: Request, env: DataEnv) => {
  const origin = request.headers.get("Origin") || "";
  return !origin || env.ALLOWED_ORIGIN.split(",").map(x => x.trim()).includes(origin);
};
function secretEqual(a: string, b: string): boolean {
  if (!a || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function actorFor(request: Request, env: DataEnv): Promise<Actor | null> {
  const bridge = request.headers.get("X-SentinelX-Bridge-Key");
  if (bridge !== null) {
    if (!env.AP_BRIDGE_KEY || !secretEqual(bridge, env.AP_BRIDGE_KEY)) return null;
    const orgToken = request.headers.get("X-SentinelX-Org-Key") || "";
    if (orgToken.length < 40 || orgToken.length > 256) return null;
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(orgToken)));
    const tokenHash = btoa(String.fromCharCode(...digest)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    const row = await env.DB.prepare("SELECT id,org_id FROM host_collectors WHERE token_hash=? AND revoked_at IS NULL").bind(tokenHash).first<{id:string;org_id:string}>();
    if (!row) return null;
    return { id: row.id, role: "service", organization_id: row.org_id, email: "collector@sentinelx.internal", display_name: "Authenticated Collector" };
  }
  return await currentUser(request, env as Parameters<typeof currentUser>[1]) as Actor | null;
}
async function audit(env: DataEnv, actor: Actor, event: string, target: string, details: string, outcome = "Success") {
  await env.DB.prepare("INSERT INTO audit_logs(id,org_id,actor_id,actor_type,event_type,target_id,details,outcome) VALUES(?,?,?,?,?,?,?,?)")
    .bind(uid(), actor.organization_id, actor.id, actor.role === "service" ? "Automation" : "Human Analyst", event, target, details.slice(0, 2000), outcome).run();
}
function parseBody(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function text(value: unknown, max = 4000): string {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}
function casePayload(row: Record<string, unknown>) {
  let payload: Record<string, unknown> = {};
  try { payload = JSON.parse(String(row.payload_json || "{}")); } catch { /* use typed fields */ }
  const cells = {
    ...payload,
    "Case ID": row.case_id, case_id: row.case_id,
    "Case Title": row.title, "AI Analysis": row.overview,
    "Source": row.source, "Severity": row.severity, "Status": row.status,
    "Created At": row.created_at, "Updated At": row.updated_at,
    "Assignee": row.assignee,
  };
  return { id: row.id, cells };
}
export async function handleDataRoute(request: Request, env: DataEnv, path: string): Promise<Response | null> {
  if (!path.startsWith("/api/cases") && !path.startsWith("/api/notes") && !path.startsWith("/api/approvals") && path !== "/api/records" &&
      !["/api/alerts","/api/investigations","/api/evidence","/api/audit","/api/assets","/api/rules","/api/telemetry","/api/approvals"].includes(path)) return null;
  if (!allowedOrigin(request, env)) return json({ error: "Origin not allowed" }, 403);
  const actor = await actorFor(request, env);
  if (!actor) return json({ error: "Authentication required" }, 401);
  const org = actor.organization_id;
  if (actor.role === "viewer" && request.method !== "GET") return json({ error: "Viewer role is read-only" }, 403);

  if (path === "/api/cases" && request.method === "GET") {
    const source = text(new URL(request.url).searchParams.get("source"), 240);
    const rows = source
      ? await env.DB.prepare("SELECT * FROM cases WHERE org_id=? AND source=? ORDER BY created_at DESC LIMIT 500").bind(org, source).all<Record<string, unknown>>()
      : await env.DB.prepare("SELECT * FROM cases WHERE org_id=? ORDER BY created_at DESC LIMIT 500").bind(org).all<Record<string, unknown>>();
    return json({ data: rows.results.map(casePayload) });
  }
  if (path === "/api/cases" && request.method === "POST") {
    const body = parseBody(await request.json().catch(() => null));
    const title = text(body?.title, 240);
    if (!title) return json({ error: "Case title is required" }, 400);
    const caseId = text(body?.caseId, 120) || "SX-" + uid().slice(0, 12).toUpperCase();
    const severity = text(body?.severity, 32) || "Unclassified";
    const status = text(body?.status, 32) || "New";
    const source = text(body?.source, 240);
    const overview = text(body?.overview, 8000);
    const assignee = text(body?.assignee, 240);
    const extra = body?.payload && typeof body.payload === "object" && !Array.isArray(body.payload) ? body.payload as Record<string, unknown> : {};
    const payload = JSON.stringify({ ...extra, assets: Array.isArray(body?.assets) ? body!.assets : (extra.assets || []), alertIds: Array.isArray(body?.alertIds) ? body!.alertIds : (extra.alertIds || []) });
    const id = uid();
    try {
      await env.DB.prepare("INSERT INTO cases(id,org_id,case_id,source_schema,title,source,severity,status,assignee,overview,payload_json) VALUES(?,?,?,'gateway',?,?,?,?,?,?,?)")
        .bind(id, org, caseId, title, source, severity, status, assignee, overview, payload).run();
      await audit(env, actor, "case_created", caseId, "Created case " + title);
      return json({ created: true, case: { id, caseId, title, severity, status } }, 201);
    } catch { return json({ error: "Case ID already exists in this organization" }, 409); }
  }
  const caseMatch = path.match(/^\/api\/cases\/([^/]+)$/);
  if (caseMatch && request.method === "POST") {
    const caseId = decodeURIComponent(caseMatch[1]);
    const body = parseBody(await request.json().catch(() => null));
    if (!body) return json({ error: "Invalid JSON body" }, 400);
    const existing = await env.DB.prepare("SELECT id FROM cases WHERE org_id=? AND (case_id=? OR id=?) LIMIT 1").bind(org, caseId, caseId).first<{id:string}>();
    if (!existing) return json({ error: "Case not found in this organization" }, 404);
    const allowed = ["status","severity","assignee","overview","title"];
    const sets: string[] = []; const values: unknown[] = [];
    for (const field of allowed) if (body[field] !== undefined) { sets.push(field + "=?"); values.push(text(body[field], field === "overview" ? 8000 : 240)); }
    if (!sets.length) return json({ error: "No supported case fields supplied" }, 400);
    sets.push("updated_at=?"); values.push(iso()); values.push(org, caseId, caseId);
    await env.DB.prepare("UPDATE cases SET " + sets.join(",") + " WHERE org_id=? AND (case_id=? OR id=?)").bind(...values).run();
    await audit(env, actor, "case_updated", caseId, "Updated fields: " + allowed.filter(k => body[k] !== undefined).join(", "));
    return json({ updated: true });
  }

  if (path === "/api/notes" && request.method === "POST") {
    const body = parseBody(await request.json().catch(() => null));
    const caseId = text(body?.caseId, 120); const note = text(body?.text, 8000);
    if (!caseId || !note) return json({ error: "caseId and note text are required" }, 400);
    const parent = await env.DB.prepare("SELECT case_id FROM cases WHERE org_id=? AND (case_id=? OR id=?) LIMIT 1").bind(org, caseId, caseId).first<{case_id:string}>();
    if (!parent) return json({ error: "Case not found in this organization" }, 404);
    const id = uid();
    await env.DB.prepare("INSERT INTO notes(id,org_id,case_id,note_type,body,author,related_evidence_reference,visibility) VALUES(?,?,?,?,?,?,?,?)")
      .bind(id, org, parent.case_id, text(body?.noteType, 64) || "Observation", note, actor.display_name || actor.email, text(body?.relatedEvidenceReference, 500) || null, text(body?.visibility, 32) || "Case Team").run();
    await audit(env, actor, "case_note_added", parent.case_id, "Analyst note added");
    return json({ created: true, note: { id, caseId: parent.case_id, text: note, author: actor.display_name || actor.email, createdAt: iso() } }, 201);
  }

  if (path === "/api/notes" && request.method === "GET") {
    const caseId = text(new URL(request.url).searchParams.get("caseId"), 120);
    if (!caseId) return json({ error: "caseId query parameter is required" }, 400);
    const rows = await env.DB.prepare("SELECT id,case_id,note_type,body,author,related_evidence_reference,visibility,created_at FROM notes WHERE org_id=? AND case_id=? ORDER BY created_at DESC LIMIT 200").bind(org, caseId).all();
    return json({ data: rows.results });
  }

  if (path === "/api/approvals" && request.method === "GET") {
    const rows = await env.DB.prepare("SELECT approval_id,case_id,action_type,target_asset,proposed_action,reason_evidence,risk_level,requested_by,status,approved_by,requested_at,decision_at,execution_status,execution_result,audit_reference,lifecycle_state,expires_at,execution_mode,verification_result FROM approvals WHERE org_id=? ORDER BY requested_at DESC LIMIT 200").bind(org).all();
    return json({ data: rows.results });
  }

  if (path === "/api/approvals" && request.method === "POST") {
    const body = parseBody(await request.json().catch(() => null));
    const actionType = text(body?.actionType, 80); const proposed = text(body?.proposedAction, 4000);
    const reason = text(body?.reasonEvidence, 4000); const risk = text(body?.riskLevel, 24);
    if (!actionType || !proposed || !reason || !["Critical","High","Medium","Low"].includes(risk)) return json({ error: "Action, proposedAction, reasonEvidence and a valid riskLevel are required" }, 400);
    const caseId = text(body?.caseId, 120);
    let canonicalCaseId: string | null = null;
    if (caseId) {
      const parent = await env.DB.prepare("SELECT case_id FROM cases WHERE org_id=? AND (case_id=? OR id=?) LIMIT 1").bind(org, caseId, caseId).first<{case_id:string}>();
      if (!parent) return json({ error: "Case not found in this organization" }, 404);
      canonicalCaseId = parent.case_id;
    }
    const id = uid(); const approvalId = "SX-APR-" + id.slice(0, 12).toUpperCase();
    await env.DB.prepare("INSERT INTO approvals(id,org_id,approval_id,case_id,action_type,target_asset,proposed_action,reason_evidence,risk_level,requested_by,status,execution_status,execution_mode) VALUES(?,?,?,?,?,?,?,?,?,?, 'Pending Approval','Not Executed','SIMULATED - no real containment')")
      .bind(id, org, approvalId, canonicalCaseId, actionType, text(body?.targetAsset, 240), proposed, reason, risk, actor.display_name || actor.email).run();
    await audit(env, actor, "approval_requested", approvalId, "Defensive action approval requested; no action executed");
    return json({ created: true, approval: { id, approvalId, status: "Pending Approval", executionStatus: "Not Executed" } }, 201);
  }

  const decisionMatch = path.match(/^\/api\/approvals\/([^/]+)\/decision$/);
  if (decisionMatch && request.method === "POST") {
    if (actor.role !== "owner" && actor.role !== "admin") return json({ error: "Approver permission required" }, 403);
    const approvalId = decodeURIComponent(decisionMatch[1]);
    const body = parseBody(await request.json().catch(() => null));
    const decision = text(body?.decision, 24);
    if (!["Approved","Rejected","Cancelled"].includes(decision)) return json({ error: "Decision must be Approved, Rejected or Cancelled" }, 400);
    const result = await env.DB.prepare("UPDATE approvals SET status=?,approved_by=?,decision_at=?,lifecycle_state=?,execution_status='Not Executed' WHERE org_id=? AND (approval_id=? OR id=?) AND status='Pending Approval'")
      .bind(decision, actor.display_name || actor.email, iso(), decision === "Approved" ? "APPROVED" : decision === "Rejected" ? "REJECTED" : "EXPIRED", org, approvalId, approvalId).run();
    if (!result.meta.changes) return json({ error: "Pending approval not found in this organization" }, 404);
    await audit(env, actor, "approval_decided", approvalId, "Approval decision: " + decision + ". Execution remains disabled.");
    return json({ updated: true, decision, executionStatus: "Not Executed" });
  }

  if (path === "/api/records" && request.method === "GET") {
    const url = new URL(request.url);
    const entity = text(url.searchParams.get("entity_type"), 80);
    const sourceTable = text(url.searchParams.get("source_table"), 80);
    const caseId = text(url.searchParams.get("case_id"), 120);
    if (!entity) return json({ error: "entity_type query parameter is required" }, 400);
    const limit = Math.min(500, Math.max(1, Number(url.searchParams.get("limit") || 200) || 200));
    const rows = sourceTable
      ? await env.DB.prepare("SELECT id,payload_json FROM soc_records WHERE org_id=? AND entity_type=? AND source_table=? AND (?='' OR case_id=?) ORDER BY created_at DESC LIMIT ?").bind(org, entity, sourceTable, caseId, caseId, limit).all<{id:string;payload_json:string}>()
      : await env.DB.prepare("SELECT id,payload_json FROM soc_records WHERE org_id=? AND entity_type=? AND (?='' OR case_id=?) ORDER BY created_at DESC LIMIT ?").bind(org, entity, caseId, caseId, limit).all<{id:string;payload_json:string}>();
    return json({ data: rows.results.map(row => { try { return { id: row.id, cells: JSON.parse(row.payload_json) }; } catch { return { id: row.id, cells: {} }; } }) });
  }
  if (path === "/api/records" && request.method === "POST") {
    if (actor.role !== "service") return json({ error: "Service-to-service authentication required" }, 403);
    const body = parseBody(await request.json().catch(() => null));
    const entity = text(body?.entity_type, 80);
    const sourceTable = text(body?.source_table, 80) || entity;
    const sourceRecordId = text(body?.source_record_id, 180) || uid();
    const caseId = text(body?.case_id, 120);
    const payload = body?.payload;
    if (!entity || !payload || typeof payload !== "object" || Array.isArray(payload)) return json({ error: "entity_type and object payload are required" }, 400);
    const serialized = JSON.stringify(payload);
    if (serialized.length > 100000) return json({ error: "Record payload is too large" }, 413);
    if (caseId) {
      const parent = await env.DB.prepare("SELECT 1 AS ok FROM cases WHERE org_id=? AND case_id=? LIMIT 1").bind(org, caseId).first();
      if (!parent) return json({ error: "Case not found in this organization" }, 404);
    }
    const id = uid();
    await env.DB.prepare("INSERT INTO soc_records(id,org_id,entity_type,source_table,source_record_id,case_id,payload_json) VALUES(?,?,?,?,?,?,?) ON CONFLICT(org_id,entity_type,source_table,source_record_id) DO UPDATE SET case_id=excluded.case_id,payload_json=excluded.payload_json,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')")
      .bind(id, org, entity, sourceTable, sourceRecordId, caseId || null, serialized).run();
    await audit(env, actor, "soc_record_upserted", sourceRecordId, "Stored " + entity + " record in D1");
    return json({ stored: true, entity_type: entity, source_record_id: sourceRecordId }, 201);
  }

  const entityMap: Record<string,string> = {
    "/api/alerts":"findings", "/api/investigations":"correlation_investigations", "/api/evidence":"evidence",
    "/api/audit":"audit", "/api/assets":"assets", "/api/rules":"rules", "/api/telemetry":"telemetry_intake",
  };
  const entity = entityMap[path];
  if (entity && request.method === "GET") {
    if (entity === "audit") {
      const [legacy, current] = await Promise.all([
        env.DB.prepare("SELECT id,payload_json,created_at FROM soc_records WHERE org_id=? AND entity_type='audit' ORDER BY created_at DESC LIMIT 500").bind(org).all<{id:string;payload_json:string;created_at:string}>(),
        env.DB.prepare("SELECT id,actor_type,event_type,target_id,details,outcome,occurred_at FROM audit_logs WHERE org_id=? ORDER BY occurred_at DESC LIMIT 500").bind(org).all<{id:string;actor_type:string;event_type:string;target_id:string|null;details:string;outcome:string;occurred_at:string}>()
      ]);
      const oldRows = legacy.results.map(row => { try { return { id: row.id, cells: JSON.parse(row.payload_json) }; } catch { return { id: row.id, cells: {} }; } });
      const newRows = current.results.map(row => ({ id: row.id, cells: { "Audit ID": row.id, "Timestamp": row.occurred_at, "Case ID": row.target_id, "Actor Type": row.actor_type, "Actor": "Authenticated analyst", "Event Type": row.event_type, "Details": row.details, "Outcome": row.outcome } }));
      return json({ data: [...newRows, ...oldRows] });
    }
    const rows = await env.DB.prepare("SELECT id,payload_json FROM soc_records WHERE org_id=? AND entity_type=? ORDER BY created_at DESC LIMIT 500")
      .bind(org, entity).all<{id:string;payload_json:string}>();
    return json({ data: rows.results.map(row => { try { return { id: row.id, cells: JSON.parse(row.payload_json) }; } catch { return { id: row.id, cells: {} }; } }) });
  }
  return json({ error: "Method not allowed" }, 405);
}
