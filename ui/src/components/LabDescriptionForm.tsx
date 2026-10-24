import { useState, type FormEvent } from "react";
import { Button } from "./ui/Button";
import { Card, CardBody, CardHeader } from "./ui/Card";
import { Textarea } from "./ui/Textarea";

interface LabDescriptionFormProps {
  busy: boolean;
  disabled: boolean;
  onSubmit: (description: string) => Promise<void>;
}

export function LabDescriptionForm({ busy, disabled, onSubmit }: LabDescriptionFormProps) {
  const [description, setDescription] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = description.trim();
    if (!trimmed) {
      setLocalError("Describe the site you want the lab to contain.");
      return;
    }
    if (trimmed.length > 2000) {
      setLocalError("Keep the description under 2,000 characters.");
      return;
    }
    setLocalError(null);
    await onSubmit(trimmed);
  }

  return (
    <Card>
      <CardHeader>
        <div className="eyebrow">01 / Define the lab</div>
        <h2>Describe the vulnerable site</h2>
        <p>Give the builder the product shape and learner context. The execution contract remains fixed to a SQL-injection lesson.</p>
      </CardHeader>
      <CardBody>
        <form onSubmit={handleSubmit} className="stack-lg">
          <div className="field">
            <label htmlFor="lab-description">Site description</label>
            <Textarea
              id="lab-description"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              placeholder="Example: Create a small product search page for a SQL injection lesson."
              maxLength={2000}
              aria-required="true"
              disabled={disabled}
              aria-describedby="description-help description-error"
            />
            <div id="description-help" className="field-meta">
              <span>Natural language is fine. No commands, credentials, paths, or provider settings.</span>
              <span>{description.length}/2000</span>
            </div>
            {localError && <p id="description-error" className="field-error" role="alert">{localError}</p>}
          </div>
          <div className="capability-row">
            <span className="capability-dot" aria-hidden="true" />
            <div>
              <strong>SQL injection</strong>
              <span>Fixed challenge contract · private verification enabled</span>
            </div>
          </div>
          <Button type="submit" disabled={busy || disabled}>
            {busy ? "Starting isolated lab…" : "Generate lab"}
            <span aria-hidden="true">↗</span>
          </Button>
        </form>
      </CardBody>
    </Card>
  );
}
