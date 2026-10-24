import type { LabPhase } from "../types";
import { Badge } from "./ui/Badge";
import { Card, CardBody, CardHeader } from "./ui/Card";
import { Progress } from "./ui/Progress";

const phases: Array<{ id: LabPhase; label: string; note: string }> = [
  { id: "queued", label: "Queued", note: "Request accepted" },
  { id: "generating", label: "Generating", note: "Building in Celesto" },
  { id: "verifying", label: "Verifying", note: "Private checks" },
  { id: "awaiting_publication", label: "Awaiting publish", note: "Your approval" },
  { id: "published", label: "Published", note: "Public lease active" },
  { id: "cleaned_up", label: "Cleaned up", note: "Route revoked" },
];

interface LabProgressProps {
  phase: LabPhase | null;
  message: string;
}

export function LabProgress({ phase, message }: LabProgressProps) {
  const currentIndex = phase === "cleaning_up" ? 5 : phases.findIndex((item) => item.id === phase);
  const progressValue = phase === "failed" ? 0 : Math.max(0, ((currentIndex + 1) / phases.length) * 100);

  return (
    <Card>
      <CardHeader className="progress-header">
        <div>
          <div className="eyebrow">02 / Observe execution</div>
          <h2>Lab lifecycle</h2>
        </div>
        <Badge tone={phase === "failed" ? "danger" : phase === "published" ? "success" : phase ? "active" : "neutral"}>
          {phase ? phase.replaceAll("_", " ") : "idle"}
        </Badge>
      </CardHeader>
      <CardBody>
        <p className="progress-message" role="status" aria-live="polite">{message}</p>
        <Progress value={progressValue} label="Lab lifecycle progress" />
        <ol className="phase-list">
          {phases.map((item, index) => {
            const complete = currentIndex >= index && phase !== "failed";
            const current = item.id === phase || (phase === "cleaning_up" && item.id === "published");
            return (
              <li key={item.id} className={`${complete ? "phase-complete" : ""} ${current ? "phase-current" : ""}`}>
                <span className="phase-marker" aria-hidden="true">{complete ? "✓" : String(index + 1).padStart(2, "0")}</span>
                <span><strong>{item.label}</strong><small>{item.note}</small></span>
              </li>
            );
          })}
        </ol>
        {phase === "failed" && <p className="inline-warning">The run stopped safely. Start a new lab after cleanup is confirmed.</p>}
      </CardBody>
    </Card>
  );
}
