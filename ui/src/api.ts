import {
  ApiError,
  type ApiErrorBody,
  type AppConfig,
  type CommandRow,
  type FlagResult,
  type LabSnapshot,
  type RunRow,
  type VulnerabilityId,
  type VulnerabilityMode,
} from "./types";

// Access code (when the server requires one) is kept only in this tab's memory.
let accessCode: string | null = null;
export function setAccessCode(code: string | null) {
  accessCode = code && code.trim() ? code.trim() : null;
}
export function getAccessCode(): string | null {
  return accessCode;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((init?.headers as Record<string, string>) ?? {}),
  };
  if (accessCode) headers["X-Access-Code"] = accessCode;
  const response = await fetch(path, { ...init, headers });
  if (!response.ok) {
    let body: ApiErrorBody = {};
    try {
      body = (await response.json()) as ApiErrorBody;
    } catch {
      body = {};
    }
    throw new ApiError(
      body.error?.code ?? "request_failed",
      body.error?.message ?? "The control plane could not complete that request.",
      response.status,
    );
  }
  return (await response.json()) as T;
}

export function getConfig(): Promise<AppConfig> {
  return request<AppConfig>("/api/config");
}

export function getRuns(): Promise<RunRow[]> {
  return request<RunRow[]>("/api/runs");
}

export function getCommands(): Promise<CommandRow[]> {
  return request<CommandRow[]>("/api/commands");
}

export function createLab(
  description: string,
  mode: VulnerabilityMode,
  vulnerabilities: VulnerabilityId[],
): Promise<LabSnapshot> {
  return request<LabSnapshot>("/api/labs", {
    method: "POST",
    body: JSON.stringify({ description, mode, vulnerabilities }),
  });
}

export function getLab(runId: string): Promise<LabSnapshot> {
  return request<LabSnapshot>(`/api/labs/${encodeURIComponent(runId)}`);
}

export function approvePublish(runId: string): Promise<LabSnapshot> {
  return request<LabSnapshot>(`/api/labs/${encodeURIComponent(runId)}/approve-publish`, { method: "POST" });
}

export function destroyLab(runId: string): Promise<LabSnapshot> {
  return request<LabSnapshot>(`/api/labs/${encodeURIComponent(runId)}/destroy`, { method: "POST" });
}

export function submitFlag(runId: string, flag: string): Promise<FlagResult> {
  return request<FlagResult>(`/api/labs/${encodeURIComponent(runId)}/submit-flag`, {
    method: "POST",
    body: JSON.stringify({ flag }),
  });
}

// Subscribe to the live step timeline over Server-Sent Events. Returns a
// cleanup function that closes the stream.
export function subscribeLab(
  runId: string,
  onSnapshot: (snapshot: LabSnapshot) => void,
): () => void {
  const source = new EventSource(`/api/labs/${encodeURIComponent(runId)}/events`);
  source.onmessage = (event) => {
    try {
      onSnapshot(JSON.parse(event.data) as LabSnapshot);
    } catch {
      /* ignore malformed keep-alive frames */
    }
  };
  source.onerror = () => {
    /* the browser retries automatically; the poller is the safety net */
  };
  return () => source.close();
}
