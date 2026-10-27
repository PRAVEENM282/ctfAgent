import { ApiError, type ApiErrorBody, type LabSnapshot, type VulnerabilityId, type VulnerabilityMode } from "./types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!response.ok) {
    let body: ApiErrorBody = {};
    try {
      body = (await response.json()) as ApiErrorBody;
    } catch {
      body = {};
    }
    throw new ApiError(
      body.error?.code ?? "request_failed",
      body.error?.message ?? "The local control plane could not complete that request.",
      response.status,
    );
  }
  return (await response.json()) as T;
}

export function createLab(
  description: string,
  mode: VulnerabilityMode = "single",
  vulnerabilities: VulnerabilityId[] = ["sql_injection"],
): Promise<LabSnapshot> {
  return request<LabSnapshot>("/api/labs", {
    method: "POST",
    body: JSON.stringify({ description, mode, vulnerabilities }),
  });
}

export function getLab(runId: string): Promise<LabSnapshot> {
  return request<LabSnapshot>(`/api/labs/${encodeURIComponent(runId)}`);
}

export function publishLab(runId: string): Promise<LabSnapshot> {
  return request<LabSnapshot>(`/api/labs/${encodeURIComponent(runId)}/publish`, {
    method: "POST",
  });
}

export function stopLab(runId: string): Promise<LabSnapshot> {
  return request<LabSnapshot>(`/api/labs/${encodeURIComponent(runId)}/stop`, {
    method: "POST",
  });
}
