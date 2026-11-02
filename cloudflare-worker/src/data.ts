import { currentUser } from "./auth";

interface DataEnv { DB: D1Database; ALLOWED_ORIGIN: string; }
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
async function actorFor(request: Request, env: DataEnv): Promise<Actor | null> {
  return await currentUser(request, env as Parameters<typeof currentUser>[1]) as Actor | null;
}
async function audit(env: DataEnv, actor: Actor, event: string, target: string, details: string, outcome = "Success") {
  await env.DB.prepare("INSERT INTO audit_logs(id,org_id,actor_id,actor_type,event_type,target_id,details,outcome) VALUES(?,?,?,?,?,?,?,?)")
    .bind(uid(), actor.organization_id, actor.id, "Human Analyst", event, target, details.slice(0, 2000), outcome).run();
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
    "Case ID": row.case_id, case_id: row.case_id,
    "Case Title": row.title, "AI Analysis": row.overview,
    "Source": row.source, "Severity": row.severity, "Status": row.status,
    "Created At": row.created_at, "Updated At": row.updated_at,
    "Assignee": row.assignee, ...payload,
  };
  return { id: row.id, cells };
}
export async function handleDataRoute(request: Request, env: DataEnv, path: string): Promise<Response | null> {
  if (!path.startsWith("/api/cases") && !path.startsWith("/api/notes") && !path.startsWith("/api/approvals") &&
      !["/api/alerts","/api/investigations","/api/evidence","/api/audit","/api/assets","/api/rules","/api/telemetry","/api/integrations"].includes(path)) return null;
  if (!allowedOrigin(request, env)) return json({ error: "Origin not allowed" }, 403);
  const actor = await actorFor(request, env);
  if (!actor) return json({ error: "Authentication required" }, 401);
  const org = actor.organization_id;

  if (path === "/api/cases" && request.method === "GET") {
    const rows = await env.DB.prepare("SELECT * FROM cases WHERE org_id=? ORDER BY created_at DESC LIMIT 500").bind(org).all<Record<string, unknown>>();
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
    const payload = JSON.stringify({ assets: Array.isArray(body?.assets) ? body!.assets : [], alertIds: Array.isArray(body?.alertIds) ? body!.alertIds : [] });
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
      .bind(id, org, parent.case_id, text(body?.noteType, 64) || "Observation", note, text(body?.author, 240) || actor.display_name || actor.email, text(body?.relatedEvidenceReference, 500) || null, text(body?.visibility, 32) || "Case Team").run();
    await audit(env, actor, "case_note_added", parent.case_id, "Analyst note added");
    return json({ created: true, note: { id, caseId: parent.case_id, text: note, author: actor.display_name || actor.email, createdAt: iso() } }, 201);
  }

  if (path === "/api/notes" && request.method === "GET") {
    const caseId = text(new URL(request.url).searchParams.get("caseId"), 120);
    if (!caseId) return json({ error: "caseId query parameter is required" }, 400);
    const rows = await env.DB.prepare("SELECT id,case_id,note_type,body,author,related_evidence_reference,visibility,created_at FROM notes WHERE org_id=? AND case_id=? ORDER BY created_at DESC LIMIT 200").bind(org, caseId).all();
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

  const entityMap: Record<string,string> = {
    "/api/alerts":"findings", "/api/investigations":"investigations", "/api/evidence":"evidence",
    "/api/audit":"audit", "/api/assets":"assets", "/api/rules":"rules", "/api/telemetry":"telemetry",
    "/api/integrations":"integrations",
  };
  const entity = entityMap[path];
  if (entity && request.method === "GET") {
    const rows = await env.DB.prepare("SELECT id,payload_json FROM soc_records WHERE org_id=? AND entity_type=? ORDER BY created_at DESC LIMIT 500")
      .bind(org, entity).all<{id:string;payload_json:string}>();
    return json({ data: rows.results.map(row => { try { return { id: row.id, cells: JSON.parse(row.payload_json) }; } catch { return { id: row.id, cells: {} }; } }) });
  }
  return json({ error: "Method not allowed" }, 405);
}
