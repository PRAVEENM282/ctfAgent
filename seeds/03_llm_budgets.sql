-- Idempotent M5 provider-budget ledger. Apply this file to both fresh and existing volumes.
ALTER TABLE runs ADD COLUMN IF NOT EXISTS llm_cost_method TEXT
    CHECK (llm_cost_method IS NULL OR llm_cost_method = 'computed_from_tokens');
ALTER TABLE runs ADD COLUMN IF NOT EXISTS llm_provider TEXT;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS llm_model TEXT;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS llm_rate_source TEXT;

CREATE TABLE IF NOT EXISTS llm_attempt_budgets (
    attempt_id TEXT PRIMARY KEY REFERENCES runs (attempt_id) ON DELETE CASCADE,
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    batch_id TEXT,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    max_http_attempts INTEGER NOT NULL CHECK (max_http_attempts > 0),
    max_token_budget BIGINT NOT NULL CHECK (max_token_budget > 0),
    time_budget_s DOUBLE PRECISION NOT NULL CHECK (time_budget_s > 0),
    max_retries INTEGER NOT NULL CHECK (max_retries >= 0),
    daily_request_limit INTEGER NOT NULL CHECK (daily_request_limit > 0),
    daily_token_limit BIGINT NOT NULL CHECK (daily_token_limit > 0),
    reserved_requests INTEGER NOT NULL DEFAULT 0 CHECK (reserved_requests >= 0),
    reserved_tokens BIGINT NOT NULL DEFAULT 0 CHECK (reserved_tokens >= 0),
    consumed_tokens BIGINT NOT NULL DEFAULT 0 CHECK (consumed_tokens >= 0),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'completed', 'released')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS llm_provider_daily_usage (
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    usage_date DATE NOT NULL DEFAULT CURRENT_DATE,
    request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    reserved_token_count BIGINT NOT NULL DEFAULT 0 CHECK (reserved_token_count >= 0),
    consumed_token_count BIGINT NOT NULL DEFAULT 0 CHECK (consumed_token_count >= 0),
    PRIMARY KEY (provider, model, usage_date)
);

CREATE TABLE IF NOT EXISTS llm_requests (
    request_id BIGSERIAL PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES llm_attempt_budgets (attempt_id) ON DELETE CASCADE,
    retry_index INTEGER NOT NULL CHECK (retry_index >= 0),
    status TEXT NOT NULL CHECK (status IN ('reserved', 'sent', 'succeeded', 'failed', 'released')),
    reserved_tokens BIGINT NOT NULL CHECK (reserved_tokens > 0),
    input_tokens BIGINT NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens BIGINT NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    total_tokens BIGINT NOT NULL DEFAULT 0 CHECK (total_tokens >= 0),
    http_status INTEGER,
    response_model TEXT,
    response_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_llm_requests_attempt ON llm_requests (attempt_id, request_id);
CREATE INDEX IF NOT EXISTS idx_llm_requests_created ON llm_requests (created_at, request_id);
