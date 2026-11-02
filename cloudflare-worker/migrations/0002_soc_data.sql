-- SentinelX tenant-scoped SOC data.
-- Authentication tables remain in place; all workspace-owned SOC records use org_id.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  case_id TEXT NOT NULL,
  source_schema TEXT NOT NULL DEFAULT 'gateway',
  title TEXT NOT NULL,
  source TEXT,
  severity TEXT NOT NULL DEFAULT 'Unclassified',
  status TEXT NOT NULL DEFAULT 'New',
  assignee TEXT,
  overview TEXT,
  payload_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(org_id, source_schema, case_id)
);
CREATE INDEX IF NOT EXISTS idx_cases_org_created ON cases(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_org_status ON cases(org_id, status);

CREATE TABLE IF NOT EXISTS notes (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  case_id TEXT NOT NULL,
  note_type TEXT NOT NULL DEFAULT 'Observation',
  body TEXT NOT NULL,
  author TEXT NOT NULL,
  related_evidence_reference TEXT,
  visibility TEXT NOT NULL DEFAULT 'Case Team',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  FOREIGN KEY(org_id, case_id) REFERENCES cases(org_id, case_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_notes_org_case ON notes(org_id, case_id, created_at DESC);

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  approval_id TEXT NOT NULL,
  case_id TEXT,
  action_type TEXT NOT NULL,
  target_asset TEXT,
  proposed_action TEXT NOT NULL,
  reason_evidence TEXT NOT NULL,
  risk_level TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending Approval',
  approved_by TEXT,
  requested_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  decision_at TEXT,
  execution_status TEXT NOT NULL DEFAULT 'Not Executed',
  execution_result TEXT,
  audit_reference TEXT,
  lifecycle_state TEXT NOT NULL DEFAULT 'PENDING_APPROVAL',
  expires_at TEXT,
  action_binding_hash TEXT,
  execution_mode TEXT NOT NULL DEFAULT 'SIMULATED - no real containment',
  verification_result TEXT,
  payload_json TEXT NOT NULL DEFAULT '{}',
  UNIQUE(org_id, approval_id),
  FOREIGN KEY(org_id, case_id) REFERENCES cases(org_id, case_id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_org_status ON approvals(org_id, status, requested_at DESC);

CREATE TABLE IF NOT EXISTS soc_records (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  entity_type TEXT NOT NULL,
  source_table TEXT NOT NULL,
  source_record_id TEXT NOT NULL,
  case_id TEXT,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(org_id, entity_type, source_table, source_record_id)
);
CREATE INDEX IF NOT EXISTS idx_soc_records_org_type ON soc_records(org_id, entity_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_soc_records_org_case ON soc_records(org_id, case_id);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  actor_id TEXT,
  actor_type TEXT NOT NULL,
  event_type TEXT NOT NULL,
  target_id TEXT,
  details TEXT NOT NULL DEFAULT '',
  outcome TEXT NOT NULL DEFAULT 'Success',
  occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_logs(org_id, occurred_at DESC);
