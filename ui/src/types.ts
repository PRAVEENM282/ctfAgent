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
export type StepStatus = "pending" | "running" | "ok" | "failed" | "skipped";

export interface LabStep {
  key: string;
  label: string;
  status: StepStatus;
}

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
  sandbox_name: string | null;
  model: string | null;
  boot_to_ready_s: number | null;
  egress_status: string | null;
  llm_fallback_used: boolean;
  local_preview: boolean;
  solved: boolean;
  flag_submissions: number;
  steps: LabStep[];
  hints: string[];
}

export interface AppConfig {
  celesto_provider: "local" | "cloud";
  celesto_backend: string;
  llm_provider: "ollama" | "openai_compatible";
  llm_model: string;
  max_active_labs: number;
  sandbox_ttl_minutes: number;
  access_code_required: boolean;
  valid: boolean;
  errors: string[];
}

export interface RunRow {
  run_id: string;
  sandbox_name: string;
  state: RunState;
  problem_id?: string;
  phase?: string;
  created_at?: string;
  [key: string]: unknown;
}

export interface CommandRow {
  ts?: string;
  timestamp?: string;
  decision: "allow" | "block";
  execution_target: string;
  origin?: string;
  command_summary?: string;
  command?: string;
  block_reason?: string | null;
  purpose?: string;
  [key: string]: unknown;
}

export interface FlagResult {
  correct: boolean;
  solved: boolean;
  submissions: number;
}

export const VULNERABILITIES: { id: VulnerabilityId; label: string }[] = [
  { id: "sql_injection", label: "SQL injection" },
  { id: "reflected_xss", label: "Reflected XSS" },
  { id: "path_traversal", label: "Path traversal" },
  { id: "idor", label: "IDOR" },
];

export interface ApiErrorBody {
  error?: { code?: string; message?: string };
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
