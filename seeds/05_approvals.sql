-- Idempotent single-use human approval records for public publication.
CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY CHECK (approval_id ~ '^approval-[a-z0-9]{16,}$'),
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    attempt_id TEXT NOT NULL,
    sandbox_name TEXT NOT NULL CHECK (sandbox_name ~ '^sbx-[a-z0-9]{8,}$'),
    action TEXT NOT NULL CHECK (action = 'publish_public_lab'),
    port INTEGER NOT NULL CHECK (port BETWEEN 1024 AND 65535),
    app_sha256 TEXT NOT NULL CHECK (app_sha256 ~ '^[0-9a-f]{64}$'),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    decision TEXT NOT NULL DEFAULT 'pending' CHECK (decision IN ('pending', 'approved', 'denied', 'expired')),
    decided_by TEXT,
    decided_at TIMESTAMPTZ,
    mode TEXT NOT NULL CHECK (mode IN ('interactive', 'pre_approved')),
    used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_approvals_pending ON approvals (decision, expires_at);
CREATE INDEX IF NOT EXISTS idx_approvals_run ON approvals (run_id, attempt_id);
