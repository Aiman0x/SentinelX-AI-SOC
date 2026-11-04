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
async function sameSecret(left: string, right: string): Promise<boolean> {
  if (!left || !right || left.length !== right.length) return false;
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", new TextEncoder().encode(left)),
    crypto.subtle.digest("SHA-256", new TextEncoder().encode(right)),
  ]);
  const x = new Uint8Array(a); const y = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}
async function collectorTokenHash(token: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)));
  return btoa(String.fromCharCode(...digest)).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/g, "");
}
async function actorFor(request: Request, env: DataEnv): Promise<Actor | null> {
  // ActivePieces must prove both platform identity (bridge key) and tenant identity
  // (a non-revoked collector token). The collector token alone is never sufficient.
  const bridgeKey = request.headers.get("X-SentinelX-Bridge-Key") || "";
  const orgToken = request.headers.get("X-SentinelX-Org-Key") || "";
  if (orgToken) {
    if (!env.AP_BRIDGE_KEY || !(await sameSecret(bridgeKey, env.AP_BRIDGE_KEY))) return null;
    const tenant = await env.DB.prepare("SELECT org_id FROM host_collectors WHERE token_hash=? AND revoked_at IS NULL")
      .bind(await collectorTokenHash(orgToken)).first<{ org_id: string }>();
    if (!tenant) return null;
    const organization = await env.DB.prepare("SELECT id FROM organizations WHERE id=? AND is_active=1")
      .bind(tenant.org_id).first<{ id: string }>();
    if (!organization) return null;
    return { id: "activepieces", role: "service", organization_id: organization.id, email: "activepieces@sentinelx.internal", display_name: "ActivePieces" };
  }
  const orgId = request.headers.get("X-SentinelX-Org-ID") || "";
  if (bridgeKey || orgId) {
    if (!env.AP_BRIDGE_KEY || !orgId || !/^[0-9a-f-]{36}$/i.test(orgId) ||
        !(await sameSecret(bridgeKey, env.AP_BRIDGE_KEY))) return null;
    const organization = await env.DB.prepare("SELECT id FROM organizations WHERE id=? AND is_active=1")
      .bind(orgId).first<{ id: string }>();
    if (!organization) return null;
    return { id: "activepieces", role: "service", organization_id: organization.id, email: "activepieces@sentinelx.internal", display_name: "ActivePieces" };
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
    "Case Title": row.title ?? payload["Case Title"], "AI Analysis": row.overview ?? payload["AI Analysis"],
    "Source": row.source ?? payload["Source"], "Severity": row.severity ?? payload["Severity"], "Status": row.status ?? payload["Status"],
    "Created At": row.created_at, "Updated At": row.updated_at,
    "Assignee": row.assignee ?? payload["Assignee"],
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
  if (actor.role === "service") {
    const serviceRead = request.method === "GET" && (
      path === "/api/cases" || /^\/api\/cases\/[^/]+$/.test(path) || path === "/api/records" ||
      ["/api/alerts", "/api/investigations", "/api/evidence", "/api/audit", "/api/assets", "/api/rules", "/api/telemetry"].includes(path)
    );
    const serviceWrite = request.method === "POST" && (
      path === "/api/cases" || /^\/api\/cases\/[^/]+$/.test(path) || path === "/api/records"
    );
    if (!serviceRead && !serviceWrite) return json({ error: "ActivePieces service scope does not permit this route" }, 403);
  }

  if (path === "/api/cases" && request.method === "GET") {
    const url = new URL(request.url);
    const source = text(url.searchParams.get("source"), 240);
    const sourceSchema = text(url.searchParams.get("source_schema"), 80);
    const fields = [1,2,3].map((n) => ({
      name: text(url.searchParams.get(n === 1 ? "field_name" : "field_name" + n), 80),
      value: text(url.searchParams.get(n === 1 ? "field_value" : "field_value" + n), 500)
    }));
    const paths = fields.map((f) => /^[A-Za-z0-9 _-]{1,80}$/.test(f.name) ? '$."' + f.name + '"' : "");
    if (fields.some((f,i) => f.name && !paths[i])) return json({ error: "Invalid field_name" }, 400);
    const rows = await env.DB.prepare("SELECT * FROM cases WHERE org_id=? AND (?='' OR source=?) AND (?='' OR source_schema=?) AND (?='' OR json_extract(payload_json,?)=?) AND (?='' OR json_extract(payload_json,?)=?) AND (?='' OR json_extract(payload_json,?)=?) ORDER BY created_at DESC LIMIT 500")
      .bind(org, source, source, sourceSchema, sourceSchema, fields[0].name, paths[0], fields[0].value, fields[1].name, paths[1], fields[1].value, fields[2].name, paths[2], fields[2].value).all<Record<string, unknown>>();
    return json({ data: rows.results.map(casePayload) });
  }
  if (path === "/api/cases" && request.method === "POST") {
    const incoming = parseBody(await request.json().catch(() => null));
    const body = parseBody(incoming?.data) || incoming;
    const title = text(body?.title, 240);
    if (!title) return json({ error: "Case title is required" }, 400);
    const caseId = text(body?.caseId, 120) || "SX-" + uid().slice(0, 12).toUpperCase();
    const severity = text(body?.severity, 32) || "Unclassified";
    const status = text(body?.status, 32) || "New";
    const source = text(body?.source, 240);
    const sourceSchema = text(body?.source_schema, 80) || "gateway";
    if (actor.role === "service" && !["sx_cases_v1", "sentinelx_cases"].includes(sourceSchema)) {
      return json({ error: "ActivePieces may only create approved telemetry/investigation case schemas" }, 403);
    }
    const overview = text(body?.overview, 8000);
    const assignee = text(body?.assignee, 240);
    const extra = body?.payload && typeof body.payload === "object" && !Array.isArray(body.payload) ? body.payload as Record<string, unknown> : {};
    const payload = JSON.stringify({ ...extra, assets: Array.isArray(body?.assets) ? body!.assets : (extra.assets || []), alertIds: Array.isArray(body?.alertIds) ? body!.alertIds : (extra.alertIds || []) });
    const id = uid();
    try {
      await env.DB.prepare("INSERT INTO cases(id,org_id,case_id,source_schema,title,source,severity,status,assignee,overview,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
        .bind(id, org, caseId, sourceSchema, title, source, severity, status, assignee, overview, payload).run();
      await audit(env, actor, "case_created", caseId, "Created case " + title);
      return json({ created: true, case: { id, caseId, title, severity, status } }, 201);
    } catch { return json({ error: "Case ID already exists in this organization" }, 409); }
  }
  const caseMatch = path.match(/^\/api\/cases\/([^/]+)$/);
  if (caseMatch && request.method === "GET") {
    const caseId = decodeURIComponent(caseMatch[1]);
    const row = await env.DB.prepare("SELECT * FROM cases WHERE org_id=? AND (case_id=? OR id=?) LIMIT 1").bind(org, caseId, caseId).first<Record<string, unknown>>();
    return row ? json({ data: [casePayload(row)] }) : json({ error: "Case not found in this organization" }, 404);
  }
  if (caseMatch && request.method === "POST") {
    const caseId = decodeURIComponent(caseMatch[1]);
    const incoming = parseBody(await request.json().catch(() => null));
    const body = parseBody(incoming?.data) || incoming;
    if (!body) return json({ error: "Invalid JSON body" }, 400);
    const existing = await env.DB.prepare("SELECT id,payload_json FROM cases WHERE org_id=? AND (case_id=? OR id=?) LIMIT 1").bind(org, caseId, caseId).first<{id:string;payload_json:string}>();
    if (!existing) return json({ error: "Case not found in this organization" }, 404);
    const allowed = ["status","severity","assignee","overview","title","source"];
    const sets: string[] = []; const values: unknown[] = [];
    for (const field of allowed) if (body[field] !== undefined) { sets.push(field + "=?"); values.push(text(body[field], field === "overview" ? 8000 : 240)); }
    if (body.payload && typeof body.payload === "object" && !Array.isArray(body.payload)) {
      let previous: Record<string, unknown> = {};
      try { previous = JSON.parse(existing.payload_json || "{}"); } catch { /* replace malformed legacy payload */ }
      sets.push("payload_json=?"); values.push(JSON.stringify({ ...previous, ...(body.payload as Record<string, unknown>) }));
    }
    if (!sets.length) return json({ error: "No supported case fields supplied" }, 400);
    sets.push("updated_at=?"); values.push(iso()); values.push(org, caseId, caseId);
    await env.DB.prepare("UPDATE cases SET " + sets.join(",") + " WHERE org_id=? AND (case_id=? OR id=?)").bind(...values).run();
    await audit(env, actor, "case_updated", caseId, "Updated fields: " + [...allowed.filter(k => body[k] !== undefined), ...(body.payload ? ["payload"] : [])].join(", "));
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
    const approvalId = text(new URL(request.url).searchParams.get("approval_id"), 180);
    const rows = approvalId
      ? await env.DB.prepare("SELECT approval_id,case_id,action_type,target_asset,proposed_action,reason_evidence,risk_level,requested_by,status,approved_by,requested_at,decision_at,execution_status,execution_result,audit_reference,lifecycle_state,expires_at,execution_mode,verification_result FROM approvals WHERE org_id=? AND approval_id=? ORDER BY requested_at DESC LIMIT 200").bind(org, approvalId).all()
      : await env.DB.prepare("SELECT approval_id,case_id,action_type,target_asset,proposed_action,reason_evidence,risk_level,requested_by,status,approved_by,requested_at,decision_at,execution_status,execution_result,audit_reference,lifecycle_state,expires_at,execution_mode,verification_result FROM approvals WHERE org_id=? ORDER BY requested_at DESC LIMIT 200").bind(org).all();
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
    const targetAsset = text(body?.targetAsset, 240);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    const actionBinding = JSON.stringify({ org, caseId: canonicalCaseId, actionType, targetAsset, proposed, reason, risk });
    const bindingHash = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(actionBinding)))));
    await env.DB.prepare("INSERT INTO approvals(id,org_id,approval_id,case_id,action_type,target_asset,proposed_action,reason_evidence,risk_level,requested_by,requested_by_actor_id,status,execution_status,execution_mode,expires_at,action_binding_hash,lifecycle_state) VALUES(?,?,?,?,?,?,?,?,?,?,?, 'Pending Approval','Not Executed','APPROVAL_REQUIRED - no action executed',?,?,'PENDING_APPROVAL')")
      .bind(id, org, approvalId, canonicalCaseId, actionType, targetAsset, proposed, reason, risk, actor.display_name || actor.email, actor.id, expiresAt, bindingHash).run();
    await audit(env, actor, "approval_requested", approvalId, "Defensive action approval requested; no action executed; expires in 15 minutes");
    return json({ created: true, approval: { id, approvalId, status: "Pending Approval", executionStatus: "Not Executed", expiresAt, actionBindingHash: bindingHash } }, 201);
  }

  const decisionMatch = path.match(/^\/api\/approvals\/([^/]+)\/decision$/);
  if (decisionMatch && request.method === "POST") {
    if (actor.role !== "owner" && actor.role !== "admin") return json({ error: "Approver permission required" }, 403);
    const approvalId = decodeURIComponent(decisionMatch[1]);
    const body = parseBody(await request.json().catch(() => null));
    const decision = text(body?.decision, 24);
    if (!["Approved","Rejected","Cancelled"].includes(decision)) return json({ error: "Decision must be Approved, Rejected or Cancelled" }, 400);
    const pending = await env.DB.prepare("SELECT approval_id,requested_by_actor_id,expires_at FROM approvals WHERE org_id=? AND (approval_id=? OR id=?) AND status='Pending Approval' LIMIT 1")
      .bind(org, approvalId, approvalId).first<{approval_id:string;requested_by_actor_id:string|null;expires_at:string|null}>();
    if (!pending) return json({ error: "Pending approval not found in this organization" }, 404);
    if (pending.requested_by_actor_id && pending.requested_by_actor_id === actor.id && decision === "Approved") {
      await audit(env, actor, "approval_self_approval_blocked", pending.approval_id, "Requester cannot approve their own response action.", "Denied");
      return json({ error: "Four-eyes control: the requester cannot approve their own action." }, 403);
    }
    if (pending.expires_at && Date.parse(pending.expires_at) <= Date.now()) {
      await env.DB.prepare("UPDATE approvals SET status='Expired',lifecycle_state='EXPIRED',execution_status='Not Executed' WHERE org_id=? AND approval_id=? AND status='Pending Approval'").bind(org, pending.approval_id).run();
      return json({ error: "Approval request expired. Create a new request after reviewing the evidence." }, 410);
    }
    const result = await env.DB.prepare("UPDATE approvals SET status=?,approved_by=?,approved_by_actor_id=?,decision_at=?,lifecycle_state=?,execution_status='Not Executed',execution_mode='APPROVED - execution still requires a separate guarded step' WHERE org_id=? AND approval_id=? AND status='Pending Approval'")
      .bind(decision, actor.display_name || actor.email, actor.id, iso(), decision === "Approved" ? "APPROVED" : decision === "Rejected" ? "REJECTED" : "EXPIRED", org, pending.approval_id).run();
    if (!result.meta.changes) return json({ error: "Approval changed concurrently; reload and review its current state." }, 409);
    await audit(env, actor, "approval_decided", pending.approval_id, "Approval decision: " + decision + ". No real action executed.");
    return json({ updated: true, decision, executionStatus: "Not Executed", nextStep: decision === "Approved" ? "A separate provider-specific executor and post-action verification are required." : undefined });
  }

  if (path === "/api/records" && request.method === "GET") {
    const url = new URL(request.url);
    const entity = text(url.searchParams.get("entity_type"), 80);
    const sourceTable = text(url.searchParams.get("source_table"), 80);
    const caseId = text(url.searchParams.get("case_id"), 120);
    const fieldName = text(url.searchParams.get("field_name"), 80);
    const fieldValue = text(url.searchParams.get("field_value"), 500);
    const fieldPath = /^[A-Za-z0-9 _-]{1,80}$/.test(fieldName) ? '$."' + fieldName + '"' : "";
    if (!entity) return json({ error: "entity_type query parameter is required" }, 400);
    if (fieldName && !fieldPath) return json({ error: "Invalid field_name" }, 400);
    const limit = Math.min(500, Math.max(1, Number(url.searchParams.get("limit") || 200) || 200));
    const rows = sourceTable
      ? await env.DB.prepare("SELECT id,payload_json FROM soc_records WHERE org_id=? AND entity_type=? AND source_table=? AND (?='' OR case_id=?) AND (?='' OR json_extract(payload_json,?)=?) ORDER BY created_at DESC LIMIT ?").bind(org, entity, sourceTable, caseId, caseId, fieldName, fieldPath, fieldValue, limit).all<{id:string;payload_json:string}>()
      : await env.DB.prepare("SELECT id,payload_json FROM soc_records WHERE org_id=? AND entity_type=? AND (?='' OR case_id=?) AND (?='' OR json_extract(payload_json,?)=?) ORDER BY created_at DESC LIMIT ?").bind(org, entity, caseId, caseId, fieldName, fieldPath, fieldValue, limit).all<{id:string;payload_json:string}>();
    return json({ data: rows.results.map(row => { try { return { id: row.id, cells: JSON.parse(row.payload_json) }; } catch { return { id: row.id, cells: {} }; } }) });
  }
  if (path === "/api/records" && request.method === "POST") {
    if (actor.role !== "service") return json({ error: "Service-to-service authentication required" }, 403);
    const body = parseBody(await request.json().catch(() => null));
    if (!body) return json({ error: "JSON object required" }, 400);
    const entity = text(body.entity_type, 80);
    const sourceTable = text(body.source_table, 80) || entity;
    if (!entity) return json({ error: "entity_type is required" }, 400);
    const items = Array.isArray(body.records) ? body.records : [body];
    if (!items.length || items.length > 200) return json({ error: "records must contain 1-200 items" }, 400);
    const statements: D1PreparedStatement[] = [];
    for (const raw of items) {
      const item = parseBody(raw);
      if (!item) return json({ error: "Each record must be a JSON object" }, 400);
      const sourceRecordId = text(item.source_record_id ?? item.finding_id ?? item.correlation_id ?? item.timeline_id ?? item.evidence_id ?? item.event_id ?? item.id, 180) || uid();
      const caseId = text(item.case_id ?? body.case_id, 120);
      const payload = item.payload && typeof item.payload === "object" && !Array.isArray(item.payload) ? item.payload : item;
      const serialized = JSON.stringify(payload);
      if (serialized.length > 100000) return json({ error: "Record payload is too large" }, 413);
      if (caseId) {
        const parent = await env.DB.prepare("SELECT 1 AS ok FROM cases WHERE org_id=? AND case_id=? LIMIT 1").bind(org, caseId).first();
        if (!parent) return json({ error: "Case not found in this organization" }, 404);
      }
      statements.push(env.DB.prepare("INSERT INTO soc_records(id,org_id,entity_type,source_table,source_record_id,case_id,payload_json) VALUES(?,?,?,?,?,?,?) ON CONFLICT(org_id,entity_type,source_table,source_record_id) DO UPDATE SET case_id=excluded.case_id,payload_json=excluded.payload_json,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')")
        .bind(uid(), org, entity, sourceTable, sourceRecordId, caseId || null, serialized));
    }
    await env.DB.batch(statements);
    await audit(env, actor, "soc_records_upserted", sourceTable, "Stored " + items.length + " " + entity + " record(s) in D1");
    return json({ stored: true, count: items.length, entity_type: entity }, 201);
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
