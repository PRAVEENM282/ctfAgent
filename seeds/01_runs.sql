CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY
        CHECK (run_id ~ '^run-[a-z0-9]{12,32}$'),
    attempt_id TEXT UNIQUE,
    parent_run_id TEXT,
    batch_id TEXT,
    sandbox_name TEXT NOT NULL
        CONSTRAINT uq_runs_sandbox_name UNIQUE
        CHECK (sandbox_name ~ '^sbx-[a-z0-9]{8,}$'),
    problem_id TEXT NOT NULL CHECK (length(problem_id) > 0),
    state TEXT NOT NULL DEFAULT 'created'
        CHECK (state IN ('created', 'ready', 'running', 'succeeded', 'failed', 'deleted')),
    execution_target TEXT NOT NULL DEFAULT 'celesto_sandbox'
        CHECK (execution_target = 'celesto_sandbox'),
    description TEXT NOT NULL DEFAULT '',
    phase TEXT NOT NULL DEFAULT 'queued'
        CONSTRAINT runs_dashboard_phase_check
        CHECK (phase IN ('queued', 'generating', 'verifying', 'awaiting_publication',
                         'published', 'cleaning_up', 'cleaned_up', 'failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    variation_seed TEXT,
    source_revision TEXT,
    spec_revision TEXT,
    error_code TEXT,
    wall_clock_s DOUBLE PRECISION CHECK (wall_clock_s IS NULL OR wall_clock_s >= 0),
    boot_to_ready_s DOUBLE PRECISION CHECK (boot_to_ready_s IS NULL OR boot_to_ready_s >= 0),
    app_ready_s DOUBLE PRECISION CHECK (app_ready_s IS NULL OR app_ready_s >= 0),
    published_url_probe_status INTEGER,
    token_input BIGINT CHECK (token_input IS NULL OR token_input >= 0),
    token_output BIGINT CHECK (token_output IS NULL OR token_output >= 0),
    llm_cost_usd NUMERIC(12, 6) CHECK (llm_cost_usd IS NULL OR llm_cost_usd >= 0),
    celesto_duration_s DOUBLE PRECISION
        CHECK (celesto_duration_s IS NULL OR celesto_duration_s >= 0),
    celesto_cost_usd NUMERIC(12, 6)
        CHECK (celesto_cost_usd IS NULL OR celesto_cost_usd >= 0),
    celesto_cost_method TEXT
        CHECK (celesto_cost_method IS NULL OR celesto_cost_method = 'computed_from_duration'),
    total_cost_usd NUMERIC(12, 6) CHECK (total_cost_usd IS NULL OR total_cost_usd >= 0)
);

CREATE INDEX IF NOT EXISTS idx_runs_created_at ON runs (created_at, run_id);

INSERT INTO runs (
    run_id,
    sandbox_name,
    problem_id,
    state,
    execution_target
)
VALUES (
    'run-seed00000001',
    'sbx-seeddemo1',
    'ctf-seed-validation',
    'deleted',
    'celesto_sandbox'
)
ON CONFLICT (run_id) DO NOTHING;
