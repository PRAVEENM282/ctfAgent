-- Idempotent publication metadata; raw URLs and tokens are never stored.
CREATE TABLE IF NOT EXISTS published_endpoints (
    publication_id BIGSERIAL PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE REFERENCES runs (run_id) ON DELETE CASCADE,
    url_sha256 TEXT NOT NULL CHECK (url_sha256 ~ '^[0-9a-f]{64}$'),
    url_host TEXT NOT NULL,
    token_sha256 TEXT CHECK (token_sha256 IS NULL OR token_sha256 ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    probe_status INTEGER,
    revoked BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_published_endpoints_active
    ON published_endpoints (revoked, expires_at);
