import { useState, type FormEvent } from "react";
import { Button } from "./ui/Button";
import { Card, CardBody, CardHeader } from "./ui/Card";
import { Textarea } from "./ui/Textarea";
import type { VulnerabilityId, VulnerabilityMode } from "../types";

const vulnerabilityProfiles: Array<{ id: VulnerabilityId; label: string; description: string }> = [
  { id: "sql_injection", label: "SQL injection", description: "Unsafe SQLite query construction" },
  { id: "reflected_xss", label: "Reflected XSS", description: "Unescaped reflected input" },
  { id: "path_traversal", label: "Path traversal", description: "Guest-local file boundary bypass" },
  { id: "idor", label: "IDOR", description: "Unprotected synthetic object lookup" },
];

interface LabDescriptionFormProps {
  busy: boolean;
  disabled: boolean;
  onSubmit: (description: string, mode: VulnerabilityMode, vulnerabilities: VulnerabilityId[]) => Promise<void>;
}

export function LabDescriptionForm({ busy, disabled, onSubmit }: LabDescriptionFormProps) {
  const [description, setDescription] = useState("");
  const [mode, setMode] = useState<VulnerabilityMode>("single");
  const [selected, setSelected] = useState<VulnerabilityId[]>(["sql_injection"]);
  const [localError, setLocalError] = useState<string | null>(null);

  function selectMode(nextMode: VulnerabilityMode) {
    setMode(nextMode);
    setSelected(nextMode === "bundle" ? vulnerabilityProfiles.map((profile) => profile.id) : [selected[0] ?? "sql_injection"]);
    setLocalError(null);
  }

  function toggleProfile(profileId: VulnerabilityId) {
    if (mode === "single") {
      setSelected([profileId]);
      return;
    }
    setSelected((current) => current.includes(profileId) ? current.filter((item) => item !== profileId) : [...current, profileId]);
  }

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
    if (!selected.length || (mode === "bundle" && selected.length < 2)) {
      setLocalError("Choose at least two profiles for a bundle.");
      return;
    }
    setLocalError(null);
    await onSubmit(trimmed, mode, selected);
  }

  return (
    <Card>
      <CardHeader>
        <div className="eyebrow">01 / Define the lab</div>
        <h2>Describe the vulnerable site</h2>
        <p>Give the builder the product shape and learner context, then choose one vulnerability or a verified bundle.</p>
      </CardHeader>
      <CardBody>
        <form onSubmit={handleSubmit} className="stack-lg">
          <div className="field">
            <label htmlFor="lab-description">Site description</label>
            <Textarea
              id="lab-description"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              placeholder="Example: Create a small product search page for an educational vulnerability lesson."
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
          <div className="field">
            <label htmlFor="vulnerability-mode">Vulnerability mode</label>
            <select
              id="vulnerability-mode"
              value={mode}
              onChange={(event) => selectMode(event.target.value as VulnerabilityMode)}
              disabled={disabled}
            >
              <option value="single">Single vulnerability</option>
              <option value="bundle">Vulnerability bundle</option>
            </select>
          </div>
          <fieldset className="profile-fieldset" disabled={disabled}>
            <legend>Vulnerability profiles</legend>
            <div className="profile-options">
              {vulnerabilityProfiles.map((profile) => (
                <label className="profile-option" key={profile.id}>
                  <input
                    type={mode === "single" ? "radio" : "checkbox"}
                    name="vulnerability-profile"
                    value={profile.id}
                    checked={selected.includes(profile.id)}
                    onChange={() => toggleProfile(profile.id)}
                  />
                  <span><strong>{profile.label}</strong><small>{profile.description}</small></span>
                </label>
              ))}
            </div>
          </fieldset>
          <div className="capability-row">
            <span className="capability-dot" aria-hidden="true" />
            <div>
              <strong>{selected.map((profileId) => vulnerabilityProfiles.find((profile) => profile.id === profileId)?.label).join(", ")}</strong>
              <span>{mode === "bundle" ? "Bundle contract · every profile must pass privately" : "Selected profile · private verification enabled"}</span>
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
