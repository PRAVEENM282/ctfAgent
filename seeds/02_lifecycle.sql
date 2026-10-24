ALTER TABLE runs
    ADD COLUMN IF NOT EXISTS celesto_cost_method TEXT;

ALTER TABLE runs
    ADD COLUMN IF NOT EXISTS celesto_duration_s DOUBLE PRECISION
        CHECK (celesto_duration_s IS NULL OR celesto_duration_s >= 0);

CREATE TABLE IF NOT EXISTS run_events (
    event_id BIGSERIAL PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs (run_id) ON DELETE CASCADE,
    from_state TEXT,
    to_state TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (
        event_type IN ('state_transition', 'transition_rejected')
    ),
    error_code TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_run_events_run_time
    ON run_events (run_id, occurred_at, event_id);
