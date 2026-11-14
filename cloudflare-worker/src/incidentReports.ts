import { currentUser } from "./auth";

type Env = { DB: D1Database };
type Actor = { id: string; organization_id: string; role: string };
type Incident = {
  id: string; incident_key: string; title: string; description: string; severity: string;
  confidence: number; status: string; first_seen: string; last_seen: string; event_count: number;
  host: string | null; username: string | null; source_ip: string | null;
  mitre_json: string; detection_json: string; evidence_count: number;
};
type EventRow = {
  event_id: string; source: string; event_type: string; severity: string; observed_at: string;
  host: string | null; username: string | null; source_ip: string | null; message: string;
};
type EvidenceRow = { id: string; rule_key: string; evidence_type: string; captured_at: string; sha256: string; payload_json: string };

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
});
const parse = <T,>(value: string, fallback: T): T => { try { return JSON.parse(value) as T; } catch { return fallback; } };
const sha256 = async (value: string) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))))
  .map(x => x.toString(16).padStart(2, "0")).join("");
const clean = (value: unknown, max = 500) => String(value ?? "—").replace(/[\r\n\t]+/g, " ").slice(0, max);

export async function handleIncidentReportRoute(request: Request, env: Env, path: string): Promise<Response | null> {
  const match = path.match(/^\/api\/incidents\/([0-9a-f-]{36})\/report$/i);
  if (!match || request.method !== "POST") return null;

  const actor = await currentUser(request, env as Parameters<typeof currentUser>[1]) as Actor | null;
  if (!actor) return json({ error: "Authentication required." }, 401);

  const incident = await env.DB.prepare(
    "SELECT id,incident_key,title,description,severity,confidence,status,first_seen,last_seen,event_count,host,username,source_ip,mitre_json,detection_json,evidence_count FROM security_incidents WHERE org_id=? AND id=?"
  ).bind(actor.organization_id, match[1]).first<Incident>();
  if (!incident) return json({ error: "Incident not found in this workspace." }, 404);

  const [eventRows, evidenceRows] = await Promise.all([
    env.DB.prepare(
      "SELECT e.event_id,e.source,e.event_type,e.severity,e.observed_at,e.host,e.username,e.source_ip,e.message FROM incident_events ie JOIN security_events e ON e.id=ie.event_row_id AND e.org_id=ie.org_id WHERE ie.org_id=? AND ie.incident_id=? ORDER BY e.observed_at ASC LIMIT 100"
    ).bind(actor.organization_id, incident.id).all<EventRow>(),
    env.DB.prepare(
      "SELECT id,rule_key,evidence_type,captured_at,sha256,payload_json FROM evidence_records WHERE org_id=? AND incident_id=? ORDER BY captured_at ASC LIMIT 200"
    ).bind(actor.organization_id, incident.id).all<EvidenceRow>()
  ]);

  const evidenceChecks = await Promise.all(evidenceRows.results.map(async item => ({
    id: item.id, ruleKey: item.rule_key, type: item.evidence_type,
    capturedAt: item.captured_at, sha256: item.sha256,
    verified: await sha256(item.payload_json) === item.sha256
  })));
  const verified = evidenceChecks.filter(x => x.verified).length;
  const detection = parse<Record<string, unknown>>(incident.detection_json, {});
  const mitre = parse<Array<{ id?: string; name?: string }>>(incident.mitre_json, []);
  const events = eventRows.results;
  const first = events[0];
  const last = events[events.length - 1];
  const timeline = events.length
    ? events.map(e => `- ${clean(e.observed_at)} — ${clean(e.event_type)} | ${clean(e.host)} | user: ${clean(e.username)} | source IP: ${clean(e.source_ip)} | ${clean(e.message, 240)}`).join("\n")
    : "- No linked event rows were available at report generation time.";
  const mitreText = mitre.length ? mitre.map(m => `- ${clean(m.id, 24)} — ${clean(m.name, 120)} (candidate mapping from detection rule)`).join("\n") : "- No MITRE ATT&CK mapping was attached to this detection.";
  const evidenceText = evidenceChecks.length
    ? evidenceChecks.map(e => `- ${e.id} | ${e.type} | SHA-256: ${e.sha256} | integrity: ${e.verified ? "verified" : "FAILED"}`).join("\n")
    : "- No evidence snapshots are linked to this incident.";
  const gaps = [
    events.length < 2 ? "Only one or no linked event is available; broader event correlation is limited." : "",
    !incident.source_ip ? "No source IP was recorded." : "",
    !incident.host ? "No host identity was recorded." : "",
    verified !== evidenceChecks.length ? "One or more evidence snapshots failed integrity verification." : "",
    "Rule-based detection is a candidate finding; authorization and business context still require analyst validation."
  ].filter(Boolean);
  const generatedAt = new Date().toISOString();
  const markdown = [
    "# SentinelX — Detection Incident Report",
    "",
    `**Incident:** ${clean(incident.title)}`,
    `**Incident ID:** ${incident.id}`,
    `**Detection rule:** ${clean(detection.ruleKey || incident.incident_key)}`,
    `**Severity:** ${incident.severity.toUpperCase()}  |  **Rule confidence:** ${incident.confidence}%  |  **Status:** ${incident.status}`,
    `**Generated:** ${generatedAt}`,
    "",
    "## Executive summary",
    clean(incident.description),
    "",
    "This is a rule-generated detection report based on tenant-scoped event records. It is not an LLM investigation and does not prove compromise.",
    "",
    "## Observed facts",
    `- Host: ${clean(incident.host)}`,
    `- Account: ${clean(incident.username)}`,
    `- Source IP: ${clean(incident.source_ip)}`,
    `- First seen: ${clean(incident.first_seen)}`,
    `- Last seen: ${clean(incident.last_seen)}`,
    `- Linked events: ${events.length} (incident aggregate: ${incident.event_count})`,
    `- Evidence snapshots: ${evidenceChecks.length}; SHA-256 verified: ${verified}`,
    "",
    "## Event timeline",
    timeline,
    "",
    "## Evidence integrity",
    evidenceText,
    "",
    "## MITRE ATT&CK candidate mapping",
    mitreText,
    "",
    "## Evidence gaps and limitations",
    ...gaps.map(g => `- ${g}`),
    "",
    "## Recommended defensive next steps",
    "- Confirm whether the activity was authorized with the system or account owner.",
    "- Review surrounding authentication, endpoint and network telemetry for the same host, account and source.",
    "- Validate the source event records and timestamps against the originating Windows or security platform.",
    "- Preserve the linked evidence snapshots and record analyst findings before any containment decision.",
    "",
    "**Response status:** No blocking, isolation, account changes or other remediation was executed by this report."
  ].join("\n");

  const reportId = crypto.randomUUID();
  const payload = JSON.stringify({
    reportId, reportType: "detection_incident", incidentId: incident.id,
    title: "Detection report: " + incident.title, markdown, generatedAt,
    eventCount: events.length, evidenceCount: evidenceChecks.length,
    verifiedEvidenceCount: verified, evidenceChecks, reportMode: "rule_based_not_llm"
  });
  await env.DB.prepare(
    "INSERT INTO soc_records(id,org_id,entity_type,source_table,source_record_id,payload_json) VALUES(?,?,?,?,?,?) ON CONFLICT(org_id,entity_type,source_table,source_record_id) DO UPDATE SET payload_json=excluded.payload_json,updated_at=CURRENT_TIMESTAMP"
  ).bind(reportId, actor.organization_id, "detection_report", "security_incidents", incident.id, payload).run();
  await env.DB.prepare(
    "INSERT INTO audit_logs(id,org_id,actor_id,actor_type,event_type,target_id,details,outcome) VALUES(?,?,?,?,?,?,?,?)"
  ).bind(crypto.randomUUID(), actor.organization_id, actor.id, "Human Analyst", "detection_report_generated", incident.id,
    JSON.stringify({ reportId, eventCount: events.length, evidenceCount: evidenceChecks.length, verifiedEvidenceCount: verified }), "Success").run();

  return json({ reportId, incidentId: incident.id, markdown, eventCount: events.length,
    evidenceCount: evidenceChecks.length, verifiedEvidenceCount: verified, generatedAt }, 201);
}
