-- MANUAL MIGRATION — already applied to the connected production D1 database.
-- Keep this outside migrations_dir: this database was updated directly before Wrangler
-- migration history was initialized. Re-running ALTER TABLE statements would fail.
-- For a fresh database, apply this after the base auth schema exists.
ALTER TABLE organization_memberships RENAME COLUMN organization_id TO org_id;
ALTER TABLE auth_sessions ADD COLUMN org_id TEXT REFERENCES organizations(id);
UPDATE auth_sessions
SET org_id = (
  SELECT m.org_id FROM organization_memberships m
  WHERE m.user_id = auth_sessions.user_id
  ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END
  LIMIT 1
)
WHERE org_id IS NULL;
ALTER TABLE auth_audit_log ADD COLUMN org_id TEXT REFERENCES organizations(id);
UPDATE auth_audit_log
SET org_id = (
  SELECT m.org_id FROM organization_memberships m
  WHERE m.user_id = auth_audit_log.user_id
  ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END
  LIMIT 1
)
WHERE org_id IS NULL AND user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_org_user ON auth_sessions(org_id,user_id,expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_audit_org_time ON auth_audit_log(org_id,occurred_at DESC);
CREATE TRIGGER IF NOT EXISTS auth_sessions_org_id_required
BEFORE INSERT ON auth_sessions
WHEN NEW.org_id IS NULL
BEGIN
  SELECT RAISE(ABORT, 'auth_sessions requires org_id');
END;
