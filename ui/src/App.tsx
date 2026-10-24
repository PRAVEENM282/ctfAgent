import { useCallback, useEffect, useState } from "react";
import { createLab, getLab, publishLab, stopLab } from "./api";
import { LabDescriptionForm } from "./components/LabDescriptionForm";
import { LabError } from "./components/LabError";
import { LabProgress } from "./components/LabProgress";
import { LabResult } from "./components/LabResult";
import { Badge } from "./components/ui/Badge";
import { type ApiError, type LabSnapshot } from "./types";

const pollingPhases = new Set(["queued", "generating", "verifying", "awaiting_publication", "cleaning_up"]);

export default function App() {
  const [snapshot, setSnapshot] = useState<LabSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [actionPending, setActionPending] = useState<"publish" | "stop" | null>(null);

  const refresh = useCallback(async (runId: string) => {
    try {
      setSnapshot(await getLab(runId));
      setError(null);
    } catch (caught) {
      setError(safeMessage(caught));
    }
  }, []);

  useEffect(() => {
    if (!snapshot || !pollingPhases.has(snapshot.phase)) return;
    const timer = window.setInterval(() => void refresh(snapshot.run_id), 2000);
    return () => window.clearInterval(timer);
  }, [refresh, snapshot]);

  async function handleCreate(description: string) {
    setSubmitting(true);
    setError(null);
    try {
      setSnapshot(await createLab(description));
    } catch (caught) {
      setError(safeMessage(caught));
      setSnapshot(null);
    } finally {
      setSubmitting(false);
    }
  }

  async function handlePublish() {
    if (!snapshot) return;
    setActionPending("publish");
    setError(null);
    try {
      setSnapshot(await publishLab(snapshot.run_id));
    } catch (caught) {
      setError(safeMessage(caught));
    } finally {
      setActionPending(null);
    }
  }

  async function handleStop() {
    if (!snapshot) return;
    setActionPending("stop");
    setError(null);
    try {
      setSnapshot(await stopLab(snapshot.run_id));
    } catch (caught) {
      setError(safeMessage(caught));
    } finally {
      setActionPending(null);
    }
  }

  const canStartNew = !snapshot || snapshot.phase === "cleaned_up" || (snapshot.phase === "failed" && snapshot.cleanup_confirmed);
  const visibleError = error ?? (snapshot?.phase === "failed" ? snapshot.message : null);

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="VulnForge home"><span className="brand-mark">V</span><span>VulnForge</span></a>
        <div className="topbar-meta">
          <Badge tone="success"><span className="status-dot" aria-hidden="true" />Local operator</Badge>
          <span className="provider-status"><span className="provider-icon" aria-hidden="true">◇</span>Bedrock-compatible provider</span>
        </div>
      </header>

      <main className="main-content">
        <section className="hero">
          <div>
            <p className="eyebrow">Isolated lab control plane</p>
            <h1>Build a vulnerable site.<br /><em>Verify it privately.</em></h1>
          </div>
          <p className="hero-copy">One controlled path from natural-language idea to a short-lived SQL-injection lab. Nothing becomes public until you approve it.</p>
        </section>

        {visibleError && <LabError message={visibleError} canRetry={canStartNew} onRetry={() => setError(null)} />}

        <section className="dashboard-grid" aria-label="Lab controls">
          <LabDescriptionForm busy={submitting} disabled={!canStartNew || actionPending !== null} onSubmit={handleCreate} />
          <LabProgress phase={snapshot?.phase ?? null} message={snapshot?.message ?? "Describe a lab to begin the isolated workflow."} />
        </section>

        <LabResult snapshot={snapshot} actionPending={actionPending} onPublish={handlePublish} onStop={handleStop} />

        <footer className="footer-note"><span className="shield-icon" aria-hidden="true">◇</span><span>Control plane stays on loopback. Published learner targets are public and intentionally unauthenticated for the active lease.</span></footer>
      </main>
    </div>
  );
}

function safeMessage(error: unknown): string {
  if (error instanceof Error && error.name === "ApiError") return error.message;
  if (error instanceof Error) return error.message;
  return "The local control plane could not complete that request.";
}
