export type LabPhase =
  | "queued"
  | "generating"
  | "verifying"
  | "awaiting_publication"
  | "published"
  | "cleaning_up"
  | "cleaned_up"
  | "failed";

export type RunState = "created" | "ready" | "running" | "succeeded" | "failed" | "deleted";
export type VulnerabilityMode = "single" | "bundle";
export type VulnerabilityId = "sql_injection" | "reflected_xss" | "path_traversal" | "idor";

export interface LabSnapshot {
  run_id: string;
  state: RunState;
  phase: LabPhase;
  message: string;
  can_publish: boolean;
  can_stop: boolean;
  cleanup_confirmed: boolean;
  public_url: string | null;
  public_access_warning: string | null;
  error_code: string | null;
}

export interface ApiErrorBody {
  error?: {
    code?: string;
    message?: string;
  };
}

export class ApiError extends Error {
  code: string;
  status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
  }
}
