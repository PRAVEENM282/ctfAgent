ALTER TABLE runs ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
ALTER TABLE runs ADD COLUMN IF NOT EXISTS phase TEXT NOT NULL DEFAULT 'queued';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'runs_dashboard_phase_check'
    ) THEN
        ALTER TABLE runs ADD CONSTRAINT runs_dashboard_phase_check CHECK (
            phase IN ('queued', 'generating', 'verifying', 'awaiting_publication',
                      'published', 'cleaning_up', 'cleaned_up', 'failed')
        );
    END IF;
END $$;
