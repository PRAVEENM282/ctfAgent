# Reliability postmortem

Provider: **local**. Ran 20 fresh labs end to end through the dashboard pipeline. 19 succeeded (95%). Median wall-clock 63.649s, p90 65.392s, median boot-to-ready 0.871s. Total observed cost $0.0.

## Failures (1)
- `sbx-da1e7084d960b257` stopped at phase `failed` (error: sandbox_create_failed).

## Cloud validation (free trial)

A 20-run cloud batch is preserved at `reports/evidence/cloud_reliability_eval.json`. Nine fresh Celesto Cloud guests completed the full create → verify → publish → delete lifecycle in ~44 s each (boot ~5 s, ~$0.0002 each) before the free trial throttled further guest creation with fast ~6 s create failures. The binding constraint is the trial's sandbox quota, not cost (the whole cloud batch spent under $0.002). The canonical reliability numbers above come from the local runtime, which has no trial quota.
