import { useState } from "react";
import type { LabSnapshot } from "../types";
import { Button } from "./ui/Button";
import { Card, CardBody, CardHeader } from "./ui/Card";

interface LabResultProps {
  snapshot: LabSnapshot | null;
  actionPending: "publish" | "stop" | null;
  onPublish: () => Promise<void>;
  onStop: () => Promise<void>;
}

export function LabResult({ snapshot, actionPending, onPublish, onStop }: LabResultProps) {
  const [copyState, setCopyState] = useState<string | null>(null);
  const published = snapshot?.phase === "published" && snapshot.public_url;

  async function copyUrl() {
    if (!snapshot?.public_url) return;
    try {
      await navigator.clipboard.writeText(snapshot.public_url);
      setCopyState("Copied");
    } catch {
      setCopyState("Copy unavailable — select the URL manually");
    }
  }

  return (
    <Card className="result-card">
      <CardHeader>
        <div className="eyebrow">03 / Access the result</div>
        <h2>{published ? "Your lab is live" : snapshot?.phase === "cleaned_up" ? "Sandbox cleaned up" : "Publication gate"}</h2>
        <p>
          {published
            ? "The verified target is reachable for the short lease shown below."
            : snapshot?.phase === "cleaned_up"
              ? "The route was revoked and the Celesto guest deletion was confirmed."
              : "The target stays private until you explicitly publish it."}
        </p>
      </CardHeader>
      <CardBody>
        {published ? (
          <div className="result-live stack-lg">
            <div className="url-box">
              <span className="url-label">Public attack URL</span>
              <code>{snapshot.public_url}</code>
            </div>
            <div className="warning-box">
              <span className="warning-icon" aria-hidden="true">!</span>
              <span>{snapshot.public_access_warning}</span>
            </div>
            <div className="button-row">
              <Button onClick={() => window.open(snapshot.public_url ?? "", "_blank", "noopener,noreferrer")}>
                Open lab ↗
              </Button>
              <Button variant="secondary" onClick={copyUrl}>Copy URL</Button>
              <Button variant="danger" onClick={() => void onStop()} disabled={actionPending !== null}>
                {actionPending === "stop" ? "Stopping…" : "Stop sandbox"}
              </Button>
            </div>
            {copyState && <p className="field-meta" role="status">{copyState}</p>}
          </div>
        ) : snapshot?.phase === "awaiting_publication" ? (
          <div className="approval-box">
            <div className="approval-icon" aria-hidden="true">✓</div>
            <div>
              <strong>Private verification passed</strong>
              <p>Publishing exposes this intentionally vulnerable site on a public, unauthenticated URL.</p>
            </div>
            <Button onClick={() => void onPublish()} disabled={actionPending !== null}>
              {actionPending === "publish" ? "Publishing…" : "Publish lab"}
            </Button>
          </div>
        ) : snapshot?.phase === "cleaned_up" ? (
          <div className="empty-result" role="status"><span className="success-mark" aria-hidden="true">✓</span><strong>Cleanup confirmed</strong><p>No public route remains active for this run.</p></div>
        ) : (
          <div className="empty-result"><span className="lock-mark" aria-hidden="true">⌁</span><strong>Nothing public yet</strong><p>Generation and private verification must complete before publication is available.</p></div>
        )}
      </CardBody>
    </Card>
  );
}
