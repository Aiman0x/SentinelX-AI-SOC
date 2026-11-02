-- Bind response approvals to authenticated actors and a durable execution attempt.
ALTER TABLE approvals ADD COLUMN requested_by_actor_id TEXT;
ALTER TABLE approvals ADD COLUMN approved_by_actor_id TEXT;
ALTER TABLE approvals ADD COLUMN execution_attempt_id TEXT;
CREATE INDEX IF NOT EXISTS idx_approvals_org_lifecycle ON approvals(org_id,lifecycle_state,expires_at);
